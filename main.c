#include "fastpbkdf2.h"
#include "hashmap.h"
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#define PRISM_HEADER_LEN 144
#define SSID_OFFSET 12
#define SIZE_ETHERNET 14
#define MAC_ADDR_LEN 6
#define LLC_LEN 8
#define TAKE_N_BITS_FROM(b, p, n) ((b) >> (p)) & ((1 << (n)) - 1)

typedef enum { WAITING,
               SUCCESS } eapol_status;

/* 802.11 MAC header */
struct sniff_802_11 {
  u_char frame_control[2];
  u_char duration_id[2];
  u_char addr1[MAC_ADDR_LEN];
  u_char addr2[MAC_ADDR_LEN];
  u_char addr3[MAC_ADDR_LEN];
  u_char sequence_control[2];
  u_char qos_control[2];
};

struct sniff_802_11_beacon {
  u_char frame_control[2];
  u_char duration_id[2];
  u_char addr1[MAC_ADDR_LEN];
  u_char addr2[MAC_ADDR_LEN];
  u_char addr3[MAC_ADDR_LEN];
  u_char sequence_control[2];
};

struct sniff_LLC {
  u_char dsap;
  u_char ssap;
  u_char control_field;
};

struct sniff_SNAP {
  u_char org_code[3];
  u_char type[2];
};

struct sniff_802_1x_auth {
  u_char version;
  u_char type;
  u_char length[2];
  u_char key_descriptor_type;
  u_char key_information[2];
  u_char key_length[2];
  u_char replay_counter[8];
  u_char wpa_key_nonce[32];
  u_char wpa_key_IV[16];
  u_char wpa_key_RSC[8];
  u_char wpa_key_ID[8];
  u_char wpa_key_MIC[16];
  u_char wpa_key_data_length[2];
};

struct ptk {
  u_char kck[16];
  u_char kek[16];
  u_char tk[16];
  u_char txk[8];
  u_char trk[8];
};

struct eapol_info {
  u_char sta_mac_address[MAC_ADDR_LEN];
  u_char ANonce[32];
  u_char SNonce[32];
  struct ptk PTK;
  eapol_status status;
};

u_char ap_mac_address[6];
u_char *ssid;
map_t *map;

u_char process_beacon(const struct pcap_pkthdr *, const u_char *);
u_char process_eapol(const struct pcap_pkthdr *, const u_char *);
u_char process_packet(const struct pcap_pkthdr *, const u_char *);
char *mac_toString(u_char *);
u_char *PRF512(u_char *, u_char *, size_t, u_char *, u_char *, u_char *, u_char *);
u_char *hexstr_to_bytes(u_char *);

int main(int argc, char *argv[]) {

  map = hashmap_new();
  char *dev = argv[1];
  ssid = argv[2];
  u_char *pwd = argv[3];
  u_char psk[32];
  char errbuf[PCAP_ERRBUF_SIZE];
  char filter_beacon[] = "wlan type mgt subtype beacon";
  char filter_eapol_on_ssid_mask[] = "wlan addr1 %s or wlan addr2 %s";
  char *filter_eapol_on_ssid;
  struct bpf_program fp;
  pcap_t *handle;
  struct pcap_pkthdr *header;
  const u_char *packet;
  char ap_mac_address_str[2 * MAC_ADDR_LEN];
  ap_mac_address_str[2 * MAC_ADDR_LEN - 1] = '\0';

  fastpbkdf2_hmac_sha1(pwd, strlen(pwd), ssid, strlen(ssid), 4096, psk, 32);
  
  u_char PMK[] = "01b809f9ab2fb5dc47984f52fb2d112e13d84ccb6b86d4a7193ec5299f851c48"; 
  //u_char passPhrase[] = "10zZz10ZZzZ";
  //u_char ssid[] = "Netgear 2/158";
  u_char A[] = "Pairwise key expansion";
  u_char APmac[] = "001e2ae0bdd0";
  u_char Clientmac[] = "cc08e0620bc8";
  u_char ANonce[] = "61c9a3f5cdcdf5fae5fd760836b8008c863aa2317022c7a202434554fb38452b";
  u_char SNonce[] = "60eff10088077f8b03a0e2fc2fc37e1fe1f30f9f7cfbcfb2826f26f3379c4318";
  u_char data[] = "0103005ffe010900200000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
  
  struct ptk *PTK = (struct ptk*) PRF512(hexstr_to_bytes(PMK), A, strlen(A), hexstr_to_bytes(APmac), hexstr_to_bytes(Clientmac), hexstr_to_bytes(ANonce), hexstr_to_bytes(SNonce));
  
  int sha_length = 16;
  u_char *MIC = malloc(16);
  HMAC(EVP_md5(), PTK->kck, 16, hexstr_to_bytes(data), 99, MIC, &sha_length);
  for(int i = 0; i < 16; i++){
    printf("%02x", MIC[i]);
  }
  printf("\n");
  
  bpf_u_int32 mask; /* The netmask of our sniffing device */
  bpf_u_int32 net;  /* The IP of our sniffing device */

  if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Can't get netmask for device %s\n", dev);
    net = 0;
    mask = 0;
  }
  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

  if(handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    return (2);
  }

  if(pcap_compile(handle, &fp, filter_beacon, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_beacon, pcap_geterr(handle));
    return (2);
  }

  if(pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_beacon, pcap_geterr(handle));
    return (2);
  }

  printf("Device: %s\n", dev);
  //Put the device in sniff loop;
  while(pcap_next_ex(handle, &header, &packet) && !process_beacon(header, packet))
    ;

  asprintf(&filter_eapol_on_ssid, filter_eapol_on_ssid_mask, mac_toString(ap_mac_address), mac_toString(ap_mac_address));

  if(pcap_compile(handle, &fp, filter_eapol_on_ssid, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_eapol_on_ssid, pcap_geterr(handle));
    return (2);
  }
  if(pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_eapol_on_ssid, pcap_geterr(handle));
    return (2);
  }
  int res = 0;
  while(pcap_next_ex(handle, &header, &packet) >= 0 && process_packet(header, packet))
    ;
  /*printf("AP mac address: ");
  for(int i = 0; i < MAC_ADDR_LEN; i++) {
    printf("%02x", ap_mac_address[i]);
  }
  printf(".\n");
  printf("%s\n", mac_toString(ap_mac_address));
  printf(filter_eapol_on_ssid, mac_toString(ap_mac_address), mac_toString(ap_mac_address));*/

  pcap_freecode(&fp);
  pcap_close(handle);
  return (0);
}

u_char process_beacon(const struct pcap_pkthdr *header, const u_char *buffer) {
  const struct sniff_802_11_beacon *hdr_802_11;
  hdr_802_11 = (struct sniff_802_11_beacon *)(buffer + PRISM_HEADER_LEN);
  int ssid_length = (int)(buffer + PRISM_HEADER_LEN + sizeof(struct sniff_802_11_beacon) + 13)[0];
  u_char beacon_ssid[ssid_length + 1];
  memcpy(beacon_ssid, (buffer + PRISM_HEADER_LEN + sizeof(struct sniff_802_11_beacon) + 14), ssid_length);
  beacon_ssid[ssid_length] = '\0';
  if(strcmp(beacon_ssid, ssid) == 0) {
    memcpy(ap_mac_address, hdr_802_11->addr2, MAC_ADDR_LEN);
    return (1);
  }
  return (0);
}

u_char process_eapol(const struct pcap_pkthdr *header, const u_char *buffer) {
  const struct sniff_802_11 *hdr_802_11;
  hdr_802_11 = (struct sniff_802_11 *)(buffer + PRISM_HEADER_LEN);
  const struct sniff_802_1x_auth *hdr_802_1x_auth;
  hdr_802_1x_auth = (struct sniff_802_1x_auth *)(buffer + PRISM_HEADER_LEN + sizeof(struct sniff_802_11) + LLC_LEN);
}

u_char process_packet(const struct pcap_pkthdr *header, const u_char *buffer) {
  const struct sniff_802_11 *hdr_802_11;
  hdr_802_11 = (struct sniff_802_11 *)(buffer + PRISM_HEADER_LEN);
  int qos_type = TAKE_N_BITS_FROM(hdr_802_11->frame_control[0], 2, 2);
  int packet_direction = TAKE_N_BITS_FROM(hdr_802_11->frame_control[1], 0, 2);
  int data_protected = TAKE_N_BITS_FROM(hdr_802_11->frame_control[1], 6, 1);
  struct eapol_info *packet_eapol_info = NULL;

  u_char *sta_address;
  if(packet_direction == 2) {
    sta_address = hdr_802_11->addr1;
  }
  else if(packet_direction == 1) {
    sta_address = hdr_802_11->addr2;
  }

  if(qos_type == 2) {
    if(data_protected) {
      if(hashmap_get(map, mac_toString(sta_address), (void **)&packet_eapol_info) == MAP_OK && packet_eapol_info->status == SUCCESS) {
        printf("%d -> I'm going to decrypt: ", header->caplen);
        for(int i = 0; i < 32; i++) {
          printf("%02x", packet_eapol_info->ANonce[i]);
        }
        printf("\n");
      }
      else {
        //printf("Can't decrypt");
      }
    }
    else {
      const struct sniff_LLC *hdr_llc;
      hdr_llc = (struct sniff_LLC *)(buffer + PRISM_HEADER_LEN + sizeof(struct sniff_802_11));
      if(hdr_llc->dsap == 0xaa) {
        const struct sniff_SNAP *hdr_snap;
        hdr_snap = (struct sniff_SNAP *)(buffer + PRISM_HEADER_LEN + sizeof(struct sniff_802_11) + sizeof(struct sniff_LLC));
        u_char ether_eapol[] = {0x88, 0x8e};
        if(memcmp(hdr_snap->type, ether_eapol, 2) == 0) {
          const struct sniff_802_1x_auth *hdr_802_1x;
          hdr_802_1x = (struct sniff_802_1x_auth *)(buffer + PRISM_HEADER_LEN + sizeof(struct sniff_802_11) + sizeof(struct sniff_LLC) + sizeof(struct sniff_SNAP));
          if(hashmap_get(map, mac_toString(sta_address), (void **)&packet_eapol_info) == MAP_MISSING) {
            if(packet_direction == 2) {
              struct eapol_info *new_packet_eapol_info = malloc(sizeof(struct eapol_info));
              hashmap_put(map, mac_toString(sta_address), new_packet_eapol_info);
              memcpy(new_packet_eapol_info->ANonce, hdr_802_1x->wpa_key_nonce, 32);
              new_packet_eapol_info->status = SUCCESS;
            }
          }
        }
      }
    }
  }
  return 1;
}


char *mac_toString(u_char *addr) {
  static char str[18];
  if(addr == NULL)
    return "";
  snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x",
           addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
  return str;
}

u_char *PRF512(u_char *PMK, u_char *A, size_t lenA, u_char *AP_addr, u_char *STA_addr, u_char *ANonce, u_char *SNonce) {
  static u_char ptk[64];
  u_char B[76];
  int i = 0;
  u_char c = 0x00;
  u_char arg[76 + lenA + 2];

  if(strcmp(AP_addr, STA_addr) < 0) {
    memcpy(B, AP_addr, MAC_ADDR_LEN);
    memcpy(B + MAC_ADDR_LEN, STA_addr, MAC_ADDR_LEN);
  }
  else {
    memcpy(B, STA_addr, MAC_ADDR_LEN);
    memcpy(B + MAC_ADDR_LEN, AP_addr, MAC_ADDR_LEN);
  }
  if(strcmp(ANonce, SNonce) < 0) {
    memcpy(B + 2 * MAC_ADDR_LEN, ANonce, 32);
    memcpy(B + 2 * MAC_ADDR_LEN + 32, SNonce, 32);
  }
  else {
    memcpy(B + 2 * MAC_ADDR_LEN, SNonce, 32);
    memcpy(B + 2 * MAC_ADDR_LEN + 32, ANonce, 32);
  }

  memcpy(arg, A, lenA);
  arg[lenA] = c;
  memcpy(arg + lenA + 1, B, 76);
  printf("\n");
  u_char hmac_sha1_res[20];
  u_char R[((512 + 159) / 160) * 20];
  u_int sha_length = 20;
  while(i <= ((512 + 159) / 160)) {
    arg[76 + lenA + 1] = 0x00 + i;
    HMAC(EVP_sha1(), PMK, 32, arg, 76 + lenA + 2, hmac_sha1_res, &sha_length);
    memcpy(R + i * 20, hmac_sha1_res, 20);
    i++;
  }
  memcpy(ptk, R, 64);
  return ptk;
}

u_char *hexstr_to_bytes(u_char *hexstr) {
  size_t len = strlen(hexstr);
  if(len % 2 != 0)
    return NULL;
  size_t final_len = len / 2;
  unsigned char *chrs = (unsigned char *)malloc((final_len) * sizeof(*chrs));
  for(size_t i = 0, j = 0; j < final_len; i += 2, j++)
    chrs[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i + 1] % 32 + 9) % 25;
  return chrs;
}