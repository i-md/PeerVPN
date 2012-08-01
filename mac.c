// 获得mac地址

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

static void err_sys(const char *errmsg)
{
        perror(errmsg);
        exit(1);
}

static void OutputMacAddress(char* prefix, unsigned char* mac) {
  int i;
  // output hardware address
  printf("%s", prefix);
  for (i = 0; i < 6; ++i) {
    printf("%x", (int)mac[i]);
    if (i != 5) {
      printf("%c", ':');
    }
  }
  printf("\n");
}

static void GetMacAddress(unsigned char* addr, const char* networkname) {
  int i, sockfd;
  struct ifreq ifr;
  struct arpreq arpr;

  strncpy(ifr.ifr_name, networkname, sizeof(ifr.ifr_name));

  if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
    err_sys("socket");
  }

  // get ip address
  if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
    err_sys("1-ioctl");
  }

  // get hardware address
  ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
  if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
    err_sys("2-ioctl");
  }

  unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
  memcpy(addr, mac, 6);
}


