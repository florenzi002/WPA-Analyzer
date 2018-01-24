#include "fastpbkdf2.h"
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

struct PTK_TKIP {
  u_char kck[16];
  u_char kek[16];
  u_char tk[16];
  u_char txk[8];
  u_char trk[8];
};

u_char ap_mac_address[6];
u_char *ssid;

u_char process_beacon(const struct pcap_pkthdr *, const u_char *);
u_char process_eapol(const struct pcap_pkthdr *, const u_char *);
char *mac_toString(u_char *);
u_char *PRF512(u_char *, u_char *, size_t, u_char *, u_char *, u_char *, u_char *);
u_char *hexstr_to_bytes(u_char *);

int main(int argc, char *argv[]) {

  char *dev = argv[1];
  ssid = argv[2];
  u_char *pwd = argv[3];
  u_char psk[32];
  char errbuf[PCAP_ERRBUF_SIZE];
  char filter_beacon[] = "wlan type mgt subtype beacon";
  char filter_eapol_on_ssid[] = "ether proto 0x888e && (wlan sa %s || wlan da %s)";
  struct bpf_program fp;
  pcap_t *handle;
  struct pcap_pkthdr *header;
  const u_char *packet;
  char ap_mac_address_str[2 * MAC_ADDR_LEN];
  ap_mac_address_str[2 * MAC_ADDR_LEN - 1] = '\0';

  fastpbkdf2_hmac_sha1(pwd, strlen(pwd), ssid, strlen(ssid), 4096, psk, 32);


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
  while(pcap_next_ex(handle, &header, &packet) && process_beacon(header, packet) < 1)
    ;

  printf("AP mac address: ");
  for(int i = 0; i < MAC_ADDR_LEN; i++) {
    printf("%02x", ap_mac_address[i]);
  }
  printf(".\n");
  printf("%s\n", mac_toString(ap_mac_address));
  printf(filter_eapol_on_ssid, mac_toString(ap_mac_address), mac_toString(ap_mac_address));

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
  printf("%s; ", beacon_ssid);
  printf("; ");
  for(int i = 0; i < 2; i++) {
    printf("%02x", hdr_802_11->duration_id[i]);
  }
  printf("; ");
  printf("addr: ");
  for(int i = 0; i < MAC_ADDR_LEN; i++) {
    printf("%02x", hdr_802_11->addr1[i]);
  }
  printf("; ");
  for(int i = 0; i < MAC_ADDR_LEN; i++) {
    printf("%02x", hdr_802_11->addr2[i]);
  }
  printf("; ");
  for(int i = 0; i < MAC_ADDR_LEN; i++) {
    printf("%02x", hdr_802_11->addr3[i]);
  }
  printf(".\n");
  if(strcmp(beacon_ssid, ssid) == 0) {
    memcpy(ap_mac_address, hdr_802_11->addr2, MAC_ADDR_LEN);
    return (1);
  }
  return (0);
}

u_char process_eapol(const struct pcap_pkthdr *header, const u_char *buffer) {
  return NULL;
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
    arg[76 + lenA + 1] = 0x00 + i ;
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