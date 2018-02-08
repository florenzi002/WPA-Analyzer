#include "fastpbkdf2.h"
#include "hashmap.h"
#include <openssl/aes.h>
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
#define IS_BIG_ENDIAN (!*(unsigned char *)&(uint16_t){1})

int SHA1_LENGTH = 16;
const char A[] = "Pairwise key expansion";
const u_char NULL_MIC[16] = {0};

typedef enum { WAITING_EAPOL_KEY_2,
               WAITING_EAPOL_KEY_3,
               WAITING_EAPOL_KEY_4,
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

/* 802.11 MAC header of beacon msgs */
struct sniff_802_11_beacon {
  u_char frame_control[2];
  u_char duration_id[2];
  u_char addr1[MAC_ADDR_LEN];
  u_char addr2[MAC_ADDR_LEN];
  u_char addr3[MAC_ADDR_LEN];
  u_char sequence_control[2];
};

/* LLC header */
struct sniff_LLC {
  u_char dsap;
  u_char ssap;
  u_char control_field;
};

/* SNAP header */
struct sniff_SNAP {
  u_char org_code[3];
  u_char type[2];
};

/* 802.1x authentication header */
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

/* IP header */
struct sniff_IP {
  u_char ip_hl : 4, ip_v : 4;
  u_char ip_dss;
  u_char ip_total_length[2];
  u_char id[2];
  u_char flags;
  u_char fragment_offset;
  u_char ttl;
  u_char protocol;
  u_char hdr_checksum[2];
  u_char src[4];
  u_char dst[4];
};

/* TCP header */
struct sniff_TCP {
  u_char src_port[2];
  u_char dst_port[2];
  u_char sqn_number[4];
  u_char ack_number[4];
  u_char hdr_len : 4, reserved1 : 4;
  u_char reserved2 : 2, urg : 1, ack : 1, psh : 1, rst : 1, syn : 1, fin : 1;
  u_char window_size[2];
  u_char tcp_checksum[2];
  u_char urgent_pointer[2];
};

/* Pairwise Temporal Key */
struct ptk {
  u_char kck[16];
  u_char kek[16];
  u_char tk[16];
  u_char txk[8];
  u_char trk[8];
};

/* Informations about 4whs status */
struct eapol_info {
  u_char sta_mac_address[MAC_ADDR_LEN];
  u_char ANonce[32];
  u_char SNonce[32];
  struct ptk PTK;
  eapol_status status;
  u_char last_replay[8];
};

u_char ap_mac_address[6];
u_char psk[32];
u_char *ssid;
map_t *map;
struct ptk *PTK0;
FILE *fd;
pcap_dumper_t *dumpfile;
long decrypted_packet_count, encrypted_packet_count;


u_char process_beacon(const struct pcap_pkthdr *, const u_char *);
u_char process_packet(const struct pcap_pkthdr *, const u_char *);
u_char packet_decrypt(const struct pcap_pkthdr *, const u_char *, struct eapol_info *);
char *mac_toString(u_char *);
u_char *PRF512(u_char *, u_char *, size_t, u_char *, u_char *, u_char *, u_char *);
u_char *hexstr_to_bytes(u_char *);
static inline void XOR(unsigned char *, unsigned char *, int len);
void dump_decrypted(u_char *, const struct pcap_pkthdr *, const u_char *);

int main(int argc, char *argv[]) {

  map = hashmap_new();   // map will contain eapol_info struct, indexed by STA mac address
  ssid = argv[3];        // WLAN SSID
  u_char *pwd = argv[4]; // WLAN password
  char errbuf[PCAP_ERRBUF_SIZE];
  char filter_beacon[] = "wlan type mgt subtype beacon";               // capture only beacon messages
  char filter_eapol_on_ssid_mask[] = "wlan addr1 %s or wlan addr2 %s"; // once found the address of AP, capture only packet from/to AP
  char *filter_eapol_on_ssid;
  struct bpf_program fp;
  pcap_t *handle;
  struct pcap_pkthdr *header;
  const u_char *packet;
  char ap_mac_address_str[2 * MAC_ADDR_LEN]; // String representation of MAC address as xx:xx:xx:xx:xx:xx
  ap_mac_address_str[2 * MAC_ADDR_LEN - 1] = '\0';
  long packet_count = 0;

  fastpbkdf2_hmac_sha1(pwd, strlen(pwd), ssid, strlen(ssid), 4096, psk, 32); // compute PSK from PWD, in WPA2-PSK PSK == PMS
  printf("PMK is: ");
  for(int i = 0; i < 32; i++){
    printf("%02x", psk[i]);
  }
  printf("\n\n");
  // open the file of the capture and an handle for its content
  handle = pcap_open_offline(argv[1], errbuf);
  if(handle == NULL) {
    fprintf(stderr, "Couldn't open file %s: %s\n", argv[1], errbuf);
    return (2);
  }

  // open a file in
  if((fd = fopen(argv[2], "w")) != NULL) {
    dumpfile = pcap_dump_fopen(handle, fd);
  }
  else {
    fprintf(stderr, "Couldn't open destination file. Exit program.");
    return -1;
  }

  if(pcap_compile(handle, &fp, filter_beacon, 0, 0) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_beacon, pcap_geterr(handle));
    return (2);
  }

  if(pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_beacon, pcap_geterr(handle));
    return (2);
  }

  // read the traffic file packet by packet looking for a beacon file of the AP broadcasting the SSID specified by the user
  // stop when reach EOF or find the beacon (and thus the AP MAC address)
  int next_ret = 0;
  while((next_ret = pcap_next_ex(handle, &header, &packet)) >= 0 && !process_beacon(header, packet))
    ;
  if(next_ret == -2) {
    fprintf(stderr, "Couldn't find the requested SSID. Reached end of capture file\n");
    return (3);
  }
  else if(next_ret == -1) {
    fprintf(stderr, "Couldn't read %s: %s\n", argv[1], pcap_geterr(handle));
    return (2);
  }

  // build the filter used for capturing traffic on specified WLAN
  asprintf(&filter_eapol_on_ssid, filter_eapol_on_ssid_mask, mac_toString(ap_mac_address), mac_toString(ap_mac_address));
  if(pcap_compile(handle, &fp, filter_eapol_on_ssid, 0, 0) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_eapol_on_ssid, pcap_geterr(handle));
    return (2);
  }
  if(pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_eapol_on_ssid, pcap_geterr(handle));
    return (2);
  }

  // start processing each packet
  while((next_ret = pcap_next_ex(handle, &header, &packet)) >= 0) {
    process_packet(header, packet);
    packet_count++;
  }
  if(next_ret == -1) {
    fprintf(stderr, "Couldn't read %s: %s\n", argv[1], pcap_geterr(handle));
    return (2);
  }
  
  printf("\ndecrypted %ld/%ld encrypted packets out of %ld on the network %s\n", decrypted_packet_count, encrypted_packet_count, packet_count, ssid);

  fclose(fd);
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

u_char process_packet(const struct pcap_pkthdr *header, const u_char *buffer) {
  const struct sniff_802_11 *hdr_802_11;
  hdr_802_11 = (struct sniff_802_11 *)(buffer + PRISM_HEADER_LEN);
  int qos_type = TAKE_N_BITS_FROM(hdr_802_11->frame_control[0], 2, 2);
  int packet_direction = TAKE_N_BITS_FROM(hdr_802_11->frame_control[1], 0, 2);
  int data_protected = TAKE_N_BITS_FROM(hdr_802_11->frame_control[1], 6, 1);
  struct eapol_info *packet_eapol_info = NULL;

  u_char *sta_mac_address;

  if(packet_direction == 2) { // from DS
    sta_mac_address = hdr_802_11->addr1;
  }
  else if(packet_direction == 1) { // to DS
    sta_mac_address = hdr_802_11->addr2;
  }
  if(qos_type == 2) {
    if(data_protected) {
      encrypted_packet_count++;
      // if we already stored a successful EAPOL handshake for that STA and we were able to decrypt it
      if(hashmap_get(map, mac_toString(sta_mac_address), (void **)&packet_eapol_info) == MAP_OK) {
        if(packet_eapol_info->status == SUCCESS && packet_decrypt(header, buffer, packet_eapol_info)) {
          // dump the decrypted packet in a file
          u_char new_segment = hdr_802_11->frame_control[1];
          new_segment &= ~(1UL << 6);
          memcpy(&hdr_802_11->frame_control[1], &new_segment, 1UL);
          dump_decrypted((u_char *)dumpfile, header, buffer);
          decrypted_packet_count++;
          // print some useful info if the packet is TCP/IP
          // const struct sniff_LLC *hdr_llc;
          // hdr_llc = (struct sniff_LLC *)(buffer + PRISM_HEADER_LEN + sizeof(struct sniff_802_11) + 8);
          // if(hdr_llc->dsap == 0xaa) {
          //   const struct sniff_SNAP *hdr_snap;
          //   hdr_snap = (struct sniff_SNAP *)(buffer + PRISM_HEADER_LEN + sizeof(struct sniff_802_11) + 8 + sizeof(struct sniff_LLC));
          //   u_char ether_IPv4[] = {0x08, 0x00};
          //   if(memcmp(hdr_snap->type, ether_IPv4, 2) == 0) {
          //     const struct sniff_IP *hdr_ip;
          //     hdr_ip = (struct sniff_IP *)(buffer + PRISM_HEADER_LEN + sizeof(struct sniff_802_11) + 8 + sizeof(struct sniff_LLC) + sizeof(struct sniff_SNAP));
          //     if(hdr_ip->protocol == 0x06) {
          //       const struct sniff_TCP *hdr_tcp;
          //       hdr_tcp = (struct sniff_TCP *)(buffer + PRISM_HEADER_LEN + sizeof(struct sniff_802_11) + 8 + sizeof(struct sniff_LLC) + sizeof(struct sniff_SNAP) + ((int)hdr_ip->ip_hl) * 32 / 8);
          //     }
          //   }
          // }
        }
        else {
          // Discard
        }
      }
      else {
        // Discard
      }
    }
    else {
      // data is unprotected
      const struct sniff_LLC *hdr_llc;
      hdr_llc = (struct sniff_LLC *)(buffer + PRISM_HEADER_LEN + sizeof(struct sniff_802_11));
      if(hdr_llc->dsap == 0xaa) {
        const struct sniff_SNAP *hdr_snap;
        hdr_snap = (struct sniff_SNAP *)(buffer + PRISM_HEADER_LEN + sizeof(struct sniff_802_11) + sizeof(struct sniff_LLC));
        u_char ether_eapol[] = {0x88, 0x8e};
        // if the packet is an EAPOL protocol message we are listening to an 4 way handshake
        if(memcmp(hdr_snap->type, ether_eapol, 2) == 0) {
          const struct sniff_802_1x_auth *hdr_802_1x;
          hdr_802_1x = (struct sniff_802_1x_auth *)(buffer + PRISM_HEADER_LEN + sizeof(struct sniff_802_11) + sizeof(struct sniff_LLC) + sizeof(struct sniff_SNAP));
          int get_from_hashmap_res = hashmap_get(map, mac_toString(sta_mac_address), (void **)&packet_eapol_info);
          // if we don't have info about WPA handshake for that STA and this message is the first one of the handshake, we start listening for the handshake to complete
          if(get_from_hashmap_res == MAP_MISSING && packet_direction == 2 && (TAKE_N_BITS_FROM(hdr_802_1x->key_information[0], 0, 1)) == 0) {
            struct eapol_info *new_packet_eapol_info = malloc(sizeof(struct eapol_info));
            hashmap_put(map, mac_toString(sta_mac_address), new_packet_eapol_info);
            memcpy(new_packet_eapol_info->ANonce, hdr_802_1x->wpa_key_nonce, 32);
            memcpy(new_packet_eapol_info->last_replay, hdr_802_1x->replay_counter, 8);
            new_packet_eapol_info->status = WAITING_EAPOL_KEY_2;
          }
          else if(get_from_hashmap_res == MAP_OK) { // if we're already listening for an handshake
            eapol_status current_status = packet_eapol_info->status;
            u_short data_length = ((hdr_802_1x->wpa_key_data_length[0] << 8) + (hdr_802_1x->wpa_key_data_length[1]));
            if(packet_direction == 2 && (TAKE_N_BITS_FROM(hdr_802_1x->key_information[0], 0, 1)) == 0) { // the AP is demanding for a new handshake
              // we remove previous informations and start listening for the new handshake
              hashmap_remove(map, mac_toString(sta_mac_address));
              struct eapol_info *new_packet_eapol_info = malloc(sizeof(struct eapol_info));
              hashmap_put(map, mac_toString(sta_mac_address), new_packet_eapol_info);
              memcpy(new_packet_eapol_info->ANonce, hdr_802_1x->wpa_key_nonce, 32);
              memcpy(new_packet_eapol_info->last_replay, hdr_802_1x->replay_counter, 8);
              new_packet_eapol_info->status = WAITING_EAPOL_KEY_2;
            }
            // is the message is the second one of the 4WHS and we were waiting for it
            if(current_status == WAITING_EAPOL_KEY_2 && packet_direction == 1 && TAKE_N_BITS_FROM(hdr_802_1x->key_information[0], 0, 1) && (TAKE_N_BITS_FROM(hdr_802_1x->key_information[1], 6, 1)) == 0 && (TAKE_N_BITS_FROM(hdr_802_1x->key_information[1], 7, 1)) == 0 && data_length > 0 && memcmp(packet_eapol_info->last_replay, hdr_802_1x->replay_counter, 8) == 0) { // msg 2
              // we have all the infos needed for the computation of PTK
              struct ptk *PTK = (struct ptk *)PRF512(psk, A, strlen(A), ap_mac_address, sta_mac_address, packet_eapol_info->ANonce, hdr_802_1x->wpa_key_nonce);
              u_char *real_MIC = malloc(16);
              u_char *calculated_MIC = malloc(16);
              memcpy(real_MIC, hdr_802_1x->wpa_key_MIC, 16);
              memcpy(hdr_802_1x->wpa_key_MIC, NULL_MIC, 16);
              HMAC(EVP_sha1(), PTK->kck, 16, hdr_802_1x, 99 + data_length, calculated_MIC, &SHA1_LENGTH);
              // if the original MIC in the packet is equal to the one we calculate using the derived PTK, then PTK is OK
              if(memcmp(real_MIC, calculated_MIC, 16) == 0) {
                memcpy(packet_eapol_info->SNonce, hdr_802_1x->wpa_key_nonce, 32);
                memcpy(&packet_eapol_info->PTK, PTK, sizeof(struct ptk));
                packet_eapol_info->status = WAITING_EAPOL_KEY_3;
              }
            }
            else if(current_status == WAITING_EAPOL_KEY_3 && packet_direction == 2 && TAKE_N_BITS_FROM(hdr_802_1x->key_information[0], 0, 1) && (TAKE_N_BITS_FROM(hdr_802_1x->key_information[1], 6, 1)) && (TAKE_N_BITS_FROM(hdr_802_1x->key_information[1], 7, 1))) { // msg 3
              u_char *KCK = packet_eapol_info->PTK.kck;
              u_char *real_MIC = malloc(16);
              u_char *calculated_MIC = malloc(16);
              memcpy(real_MIC, hdr_802_1x->wpa_key_MIC, 16);
              memcpy(hdr_802_1x->wpa_key_MIC, NULL_MIC, 16);
              HMAC(EVP_sha1(), KCK, 16, hdr_802_1x, 99 + data_length, calculated_MIC, &SHA1_LENGTH);
              // we keep checking for MIC correspondence, and if the packet is legitimate, we save the replay counter
              if(memcmp(real_MIC, calculated_MIC, 16) == 0) {
                packet_eapol_info->status = WAITING_EAPOL_KEY_4;
                // we save replay counter since msg 2 and 4 look the same except for the replay counter value
                memcpy(packet_eapol_info->last_replay, hdr_802_1x->replay_counter, 8);
              }
            }
            else if(current_status == WAITING_EAPOL_KEY_4 && packet_direction == 1 && TAKE_N_BITS_FROM(hdr_802_1x->key_information[0], 0, 1) && (TAKE_N_BITS_FROM(hdr_802_1x->key_information[1], 6, 1)) == 0 && (TAKE_N_BITS_FROM(hdr_802_1x->key_information[1], 7, 1)) == 0 && memcmp(packet_eapol_info->last_replay, hdr_802_1x->replay_counter, 8) == 0) { // msg 4
              u_char *KCK = packet_eapol_info->PTK.kck;
              u_char *real_MIC = malloc(16);
              u_char *calculated_MIC = malloc(16);
              memcpy(real_MIC, hdr_802_1x->wpa_key_MIC, 16);
              memcpy(hdr_802_1x->wpa_key_MIC, NULL_MIC, 16);
              HMAC(EVP_sha1(), KCK, 16, hdr_802_1x, 99 + data_length, calculated_MIC, &SHA1_LENGTH);
              if(memcmp(real_MIC, calculated_MIC, 16) == 0) {
                printf("Handshake completed between %s - %s\n", mac_toString(sta_mac_address), mac_toString(ap_mac_address));
                packet_eapol_info->status = SUCCESS;
              }
            }
          }
        }
      }
    }
  }
  return 1;
}

char *mac_toString(u_char *addr) {
  char str[18];
  char *res_str = malloc(18);
  if(addr == NULL)
    return "";
  snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x",
           addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
  memcpy(res_str, str, 18);
  return res_str;
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

u_char packet_decrypt(const struct pcap_pkthdr *header, const u_char *buffer, struct eapol_info *eapol_keys) {
  const struct sniff_802_11 *hdr_802_11;
  hdr_802_11 = (struct sniff_802_11 *)(buffer + PRISM_HEADER_LEN);
  int is_a4, i, n, hdr_ccmp_offset, blocks, is_qos;
  int data_len, last, offset;
  u_char ccmp_aes_ctr[16], B[16], MIC[16];
  u_char packet_number[6];

  is_a4 = (hdr_802_11->frame_control[1] & 3) == 3;
  is_qos = (hdr_802_11->frame_control[0] & 0x8C) == 0x88;
  hdr_ccmp_offset = 24 + 6 * is_a4;
  hdr_ccmp_offset += 2 * is_qos;

  data_len = header->caplen - PRISM_HEADER_LEN - hdr_ccmp_offset - 8 - 8 - 4;

  packet_number[0] = *(buffer + PRISM_HEADER_LEN + hdr_ccmp_offset + 7);
  packet_number[1] = *(buffer + PRISM_HEADER_LEN + hdr_ccmp_offset + 6);
  packet_number[2] = *(buffer + PRISM_HEADER_LEN + hdr_ccmp_offset + 5);
  packet_number[3] = *(buffer + PRISM_HEADER_LEN + hdr_ccmp_offset + 4);
  packet_number[4] = *(buffer + PRISM_HEADER_LEN + hdr_ccmp_offset + 1);
  packet_number[5] = *(buffer + PRISM_HEADER_LEN + hdr_ccmp_offset);

  //ccmp_aes_ctr [0x59|priority|src_addr|packet_number|ctr]
  ccmp_aes_ctr[0] = 0x59;
  ccmp_aes_ctr[1] = 0;
  memcpy(&ccmp_aes_ctr[2], hdr_802_11->addr2, MAC_ADDR_LEN);
  memcpy(&ccmp_aes_ctr[2 + MAC_ADDR_LEN], packet_number, 6);
  ccmp_aes_ctr[14] = (data_len >> 8) & 0xFF;
  ccmp_aes_ctr[15] = (data_len & 0xFF);

  u_char AAD[32] = {0};
  AAD[2] = hdr_802_11->frame_control[0] & 0x8F;
  AAD[3] = hdr_802_11->frame_control[1] & 0xC7;
  memcpy(AAD + 4, &(hdr_802_11->addr1), 3 * 6);
  AAD[22] = hdr_802_11->sequence_control[0] & 0x0F;

  if(is_qos) {
    memcpy(&AAD[24], hdr_802_11->qos_control, 2);
    ccmp_aes_ctr[1] = AAD[24];
    AAD[1] = 22 + 2;
  }
  else {
    memset(&AAD[24], 0, 2);
    ccmp_aes_ctr[1] = 0;
    AAD[1] = 22 + 2;
  }

  AES_KEY TK;
  AES_set_encrypt_key(eapol_keys->PTK.tk, 128, &TK);
  AES_encrypt(ccmp_aes_ctr, MIC, &TK);
  XOR(MIC, AAD, 16);
  AES_encrypt(MIC, MIC, &TK);
  XOR(MIC, AAD + 16, 16);
  AES_encrypt(MIC, MIC, &TK);

  ccmp_aes_ctr[0] &= 0x07;
  ccmp_aes_ctr[14] = ccmp_aes_ctr[15] = 0;
  AES_encrypt(ccmp_aes_ctr, B, &TK);
  XOR(buffer + header->caplen - 8 - 4, B, 8);

  blocks = (data_len + 16 - 1) / 16;
  last = data_len % 16;
  offset = hdr_ccmp_offset + 8;

  for(i = 1; i <= blocks; i++) {
    n = (last > 0 && i == blocks) ? last : 16;

    ccmp_aes_ctr[14] = (i >> 8) & 0xFF;
    ccmp_aes_ctr[15] = i & 0xFF;

    AES_encrypt(ccmp_aes_ctr, B, &TK); // S_i := E( K, A_i )
    XOR(buffer + PRISM_HEADER_LEN + offset, B, n);
    XOR(MIC, buffer + PRISM_HEADER_LEN + offset, n);
    AES_encrypt(MIC, MIC, &TK);

    offset += n;
  }

  return memcmp(buffer + PRISM_HEADER_LEN + offset, MIC, 8) == 0;
}

static inline void XOR(unsigned char *dst, unsigned char *src, int len) {
  int i;
  for(i = 0; i < len; i++)
    dst[i] ^= src[i];
}

void dump_decrypted(u_char *dumper, const struct pcap_pkthdr *header, const u_char *buffer) {
  u_char *new_buffer = malloc(header->caplen - 8);
  size_t length = PRISM_HEADER_LEN + sizeof(struct sniff_802_11);
  memcpy(new_buffer, buffer, length);
  memcpy(new_buffer + length, buffer + length + 8, header->caplen - length - 8);
  pcap_dump((u_char *)dumpfile, header, new_buffer);
  free(new_buffer);
}