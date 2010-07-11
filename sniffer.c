#include <stdio.h>

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <assert.h>

#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <ctype.h>


#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/wireless.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>



#include "sniffer.h"
#include "common.h"
#include "xmalloc.h"
#include "radiotap-parser.h"
#include "ieee80211_radiotap.h"
#include "crypt/crypto.h"



//#if QT_INTERFACE==1
#include "qt_interface.h"
//#endif



//!!!TODO LOG_ERR in xmalloc




/*TODO:
read with pcap_nex <we need to switch channels in a time>


proper exit for:

SIGABRT
SIGBUS 

SIGHUP
SIGILL
SIGINT
SIGPIPE
SIGQUIT
SIGSEGV 
SIGTERM !!!!!!!!!!!!!!!!!!!!!!!!!!!!!TODO!!!!!!!!!!!!!!!!!!
SIGTSTP
SIGSYS
   
*/


/*!TODO BUG:
1. when rd->flag_ds==3!!!! we have two bssid ?
-> untested! 2. when don't check if radiotap header is missing (bug resolved but untested due the lack of equipament)
3. we are not checking if card could be set in monitor mode
4. to verify if file exists in debug() with random
5. Japan freq 5035 5040 5045 5055 5060 5080 mHz are not converted into channels for avoiding confusion with 802.11bg channels
6. atexit try first debug()
7. we check only rsn version and not the version from vendor
8. we never check addr4! when filtering packets
9. PROBLEM IN 64 bits architectures
10. QT_INTERFACE must be tested also as a flag (after compilation) for having both Qt and console UI in the same time
11. IEEE80211 defines eapol timeout 100 ms but we consider 1 second
12.!!!! WE IGNORE some parameters when GUI
!!!13. Pcap header describes len as the packet length and not the captured packet length. We should check if we will use  header->len  or header->caplen. 
14. Implement filter when dumping pkgs
15. line with no  little/big indian
16. when recieved a new handshake the old one is deleted even if handshake was not succesfull (wpa_eapol_update(...) not working)
17. Auth version 2 not tested!

*/




//uint8_t default_channels[]=
//{
//	1, 7, 13, 2, 8, 3, 9, 4, 10, 5, 11, 6, 12, 0
//};
uint8_t default_channels[]=
{
	1, 7, 13, 2, 8, 3, 9, 4, 10, 5, 11, 6, 12, 0
	//1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0
};


uint8_t abg_channels[]=
{
	1 , 2 , 3 , 4 , 5 , 6 , 7 , 8 , 9 , 10 , 11 , 12 , 13 , 14,
	34, 36, 38, 40, 42, 44, 46, 48, 52, 56, 60, 64,
	100, 104, 108, 112, 116, 120, 124, 128, 132, 136,
	140, 149, 153, 157, 161, 165, 183, 184, 185, 187,
	188, 189, 192, 196, 0
};


uint8_t bg_channels[]=
{ 
	1 , 2 , 3 , 4 , 5 , 6 , 7 , 8 , 9 , 10 , 11 , 12 , 13 , 14, 0
};

uint8_t a_channels[]=
{
	34, 36, 38, 40, 42, 44, 46, 48, 52, 56, 60, 64,
	100, 104, 108, 112, 116, 120, 124, 128, 132, 136,
	140, 149, 153, 157, 161, 165, 183, 184, 185, 187,
	188, 189, 192, 196, 0
};

//sorry JAPAN, channels 7 8 9 11 12 16 are not included due the confusion that could create with bg channels. 
//if you are from Japan you can still use frequencies instead of channels


    //            36, 40, 44, 48, 52, 56, 60, 64,
    //            100, 104, 108, 112, 116,120, 124, 128, 132, 136, 140,
  //              149, 153, 157, 161,
   //             184, 188, 192, 196, 200, 204, 208, 212, 216




//global variables
//with all settings
struct global_variables G;



void dbg(char *fmt, ...)
{
        char buf[LOGBUFFER_SIZE] = {'\0'};
        va_list msg;

        va_start(msg,fmt);
        vsnprintf(buf, sizeof(buf), fmt, msg);
        va_end(msg);
        buf[sizeof(buf) - 1] = '\0';
        printf("\n\n---------------------------------------\n");
        printf("%s",buf);
        printf("\n---------------------------------------\n\n");

}

void dbg_hex(const char *name,const unsigned char *hex,unsigned int len)
{
	unsigned int i=0;
        printf("\n\n---------------------------------------\n");
	printf("%s:\n",name);
	while (i<len){
		printf("%02x ",hex[i++]);
	}
        printf("\n---------------------------------------\n\n");
}

void dbg_mac(const char *name,u8 mac[6])
{
	printf("%s %02x:%02x:%02x:%02x:%02x:%02x\n",name,mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}


//print log priority:LOG_ERR (system)
void log_err(int debug_level,char *fmt, ...)
{
        char buf[LOGBUFFER_SIZE] = {'\0'};
        va_list msg;
        va_start(msg,fmt);
        vsnprintf(buf, sizeof(buf), fmt, msg);
        va_end(msg);
        buf[sizeof(buf) - 1] = '\0';
//      log_write(debug_level, LOG_ERR, buf);

	printf("%s\n",buf);

	
	
#if DEBUG_MODE==1	
	if (debug_level<LEVEL10){
		debug();
		//printf("\nEXITING (DEBUG MODE IS ON)\n");
		//exit(0);	
	}
#endif	
}

void pr(const char *name,const uint8_t *x,int len)
{
	int i;

	printf("%s:",name);
	for (i=0;i<len;i++){
		printf("%02x ",x[i]);
	}
	printf("\n"); 
}


char *str_mk(char *fmt, ...)
{
        char buf[STR_BUFFER_SIZE] = {'\0'};
        va_list msg;
	char *to_return;

        va_start(msg,fmt);
        vsnprintf(buf, sizeof(buf), fmt, msg);
        va_end(msg);
        buf[sizeof(buf) - 1] = '\0';

	to_return=(char *)xmalloc(sizeof(char)*(strlen(buf)+1));
	strcpy(to_return,buf);

	return to_return;
}


//init for eapol frames
struct wpa_eapol *wpa_init()
{
	struct wpa_eapol *wpa;
	
	wpa=(struct wpa_eapol *)xmalloc(sizeof(struct wpa_eapol));
	//eapol frame
	wpa->version=0;
	memset(wpa->anonce,0,AUTH_NONCE_SIZE);
	memset(wpa->snonce,0,AUTH_NONCE_SIZE);
	memset(wpa->eapol,0,AUTH_EAPOL_SIZE_MAX);
	memset(wpa->stmac,0,HW_ADDR_SIZE);
	memset(wpa->mic,0,AUTH_MIC_SIZE);
	
	wpa->eapol_size=0;
	wpa->state=0;
	wpa->last_seen=0;
	
	return wpa;
}

//init for util informations
void rd_init(struct pkg_util_info *rd)
{
	
//	rd->enc=0;
	rd->max_rate=0;
	rd->channel=0;
	rd->signal=-1;
	rd->noise=-1;    
	rd->protocol=-1;
	rd->type=-1;
	rd->subtype=-1;
	rd->type_subtype=-1; 
	rd->flag_ds=-1;
	rd->is_protected=-1;
	memset(rd->da,0xff,sizeof(rd->da));
	memset(rd->sa,0xff,sizeof(rd->sa));
	memset(rd->bssid,0xff,sizeof(rd->bssid));
	rd->ssid[0]='\0';
	rd->seen=0;
	rd->no=0;
	rd->cipher=CIPHER_NULL;
	rd->auth=AUTH_NULL;

	
	rd->wpa=NULL;
}


void rd_destroy(struct pkg_util_info *rd)
{
	if (rd->wpa!=NULL){
		free(rd->wpa);
		rd->wpa=NULL;
	}
}

void dbg_bin(char *binname,u32 num,unsigned int size)
{
	char i;
	printf("\n%s:\n",binname);
	for (i=size*8-1;i>=0;i--){
//		printf("size:%u i:%u\n",size,i);
		printf("%d",(num>>i)&1);
		if ((i)%8==0)
			printf(" ");
	}
	printf("\n");
}	


/*
Compares if two bssid are equal

RETURN: when different: 0
	     equal    : 1
*/

int bssid_equal(const uint8_t bssid1[6],const uint8_t bssid2[6])
{
	//int i;
	
	return mac_equal(bssid1,bssid2);
	
}


/*functions for manipulating AP */

/*
finds if a bssid exist on access_point structure

RETURN: 
	NULL , when bssid not found (or is invalid)
	pointer to founded acess_point, when bssid found
*/

struct access_point *ap_find(struct access_point *last_ap,uint8_t bssid[6])
{
	struct access_point *iter;
	
	const uint8_t invalid_bssid0[6]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
	const uint8_t invalid_bssid1[6]={0x00,0x00,0x00,0x00,0x00,0x00};

	
	if (bssid_equal(bssid,invalid_bssid0)==1 || bssid_equal(bssid,invalid_bssid1)==1){
		log_err(LEVEL7,(char *)"Invalid bssid to find! (BUG?!)");
		return NULL;
	}
	
	iter=last_ap;
	
	while (iter!=NULL){
		if (bssid_equal(bssid,iter->bssid)==1){
			return iter;
		}
		iter=iter->prev;
	}
	
	return NULL;
}


//usefull when debuging
void ap_dbg(struct access_point *last_ap)
{
	
	if (last_ap==NULL){
		printf("\n\n\nNULL ACCESS POINT!!!!\n\n\n");
		return;
	}
	
	printf("\n=================================1=================\n");
	dbg_mac((char *)"BSSID",last_ap->bssid);
//	printf("LEN:%d\n\n\n",strlen(last_ap->ssid));
	if (last_ap->ssid!=NULL){
		dbg_hex((char *)"SSID:",(unsigned char *)last_ap->ssid,strlen(last_ap->ssid));
		printf("SSID: %s\n",last_ap->ssid);
	}else{
		printf("SSID: !!!NULL!!!\n");
	}
	
	printf("CHANNEL:%d\n",last_ap->channel);
	printf("POWER: %d\n",last_ap->signal_power);
	printf("NOISE: %d\n",last_ap->signal_noise);
	printf("PACKETS: %ud\n",last_ap->no_pkg);
	printf("BEACONS: %ud\n",last_ap->no_beacon);
	printf("MANAGEMENT: %ud\n",last_ap->no_management);
	printf("CONTROL: %ud\n",last_ap->no_control);
	printf("DATA: %ud\n",last_ap->no_data);
	
	printf("\n==================================================\n");
}




void print_ap(struct access_point *fap)
{
	return;
//      printf("LEN:%d\n\n\n",strlen(last_ap->ssid));
	struct access_point *ap;
	unsigned int no_line;
	unsigned int i=0;
	static time_t last_print=0;
	
	
//XXX NOT SHURE ABOUT THIS!!!!!!!!!!
//!FIXME
//TO DEACTIVATE IN OFFLINE MODE
	if (G.offline==0){
		if (time(NULL)-last_print<1){
			return;
		}
		last_print=time(NULL);
	}
	
	no_line=4;
	ap=fap;
	printf("\33[2J");

	printf("\33[%d;1H",no_line++);
	printf(" BSSID\t\t    ");
	printf("PWR");
	printf("  BEACONS");
	printf("     DATA");
	printf("  CNTRL");
	printf("   MGMT");
	printf("   CH");
	printf(" CIPHER");
	printf(" AUTH ");
	if (DEBUG_MODE==1){
		printf(" DBG_ENC ");
	}
	printf("   SSID");
	no_line++;
	while (ap!=NULL){
		i++;
		printf("\33[%d;1H",no_line++);
		//printf("\n");
		printf("%02d",ap->id);
		printf(" %02x:%02x:%02x:%02x:%02x:%02x ",ap->bssid[0],ap->bssid[1],ap->bssid[2],ap->bssid[3],ap->bssid[4],ap->bssid[5]);
		printf("%4d",ap->signal_power);
		//printf("%6d",ap->signal_noise);
		printf(" %8d",ap->no_beacon);
		printf(" %8d",ap->no_data);
		printf(" %6d",ap->no_control);
		printf(" %6d",ap->no_management);
		if (ap->channel>>7==0){
			printf(" %4d",ap->channel);
		}else{
			printf(" %3d?",ap->channel&0x7F);
		}
		
		//printf(" %02x",ap->cipher);
		if (ap->cipher==0){
			printf("       ");
		}else{
			if ((ap->cipher&CIPHER_WEP40)!=0){
				printf(" WEP40 ");
			}else{
				if ((ap->cipher&CIPHER_WEP104)!=0){
					printf(" WEP104");
				}else{
					if ((ap->cipher&CIPHER_CCMP)!=0){
						printf(" CCMP  ");
					}else{
						if ((ap->cipher&CIPHER_TKIP)!=0){
							printf(" TKIP  ");
						}else{
							if ((ap->cipher&CIPHER_PROPRIETARY)!=0){
								printf(" PROP  ");
							}else{
								if ((ap->cipher&CIPHER_WEP)!=0){
									printf(" WEP   ");
								}else{
									if ((ap->cipher&CIPHER_OPN)!=0){
										printf(" OPN   ");
									}else{
										if ((ap->cipher&CIPHER_ENC)!=0){
											printf(" ENC   ");
										}else{
											printf(" ????  ");
										}
									}
								}
							}
						}
					}
				}
			}
		}
		printf(" ");
		
		if (ap->auth==0){
			printf("     ");
		}else{
			if ((ap->auth&AUTH_RSNA)!=0){
				printf(" RSNA");
			}else{
				if ((ap->auth&AUTH_PSK)!=0){
					printf(" PSK ");
				}else{
					if ((ap->auth&AUTH_PROPRIETARY)!=0){
						printf(" PROP");
					}else{
						printf(" ????");
					}
				}
			}
		}
		
		if (DEBUG_MODE==1){
			printf(" %03x - %02x ",ap->cipher,ap->auth);
		}
			
			
		if (ap->ssid!=NULL){
			if (ap->ssid[0]!='\0'){
				printf("   %s",ap->ssid);
			}else{
				printf("   <length: 0>");
			}
			
		}else{
			printf("   NULL");
		}
		
		if (ap->wpa!=NULL || ap->wpa_new!=NULL){
			if (ap->wpa!=NULL)
				printf(" [- HANDSHAKE %02x]",ap->wpa->state);
			else
				printf(" [- HANDSHAKEN %02x]",ap->wpa_new->state);
		}
		ap=ap->next;

	}
	printf("\n");
	
	printf("\33[1;1H");
	printf("Nr AP:%u\n",i);
	printf("\33[%d;1H",++no_line);
	#if DEBUG_MODE==1
		printf("\nDebug mode on\n");
	#endif
}


void print_supported_chan_freq(void)
{
	uint16_t *x;
	int i;
	i=0;
	
	x=get_supported_freq();
	if (x!=NULL){
		printf("%s supports:\n",G.dev_name);
		while (x[i]!=0){
			printf("\tChannel %3u: %4u mHz\n",ieee80211mhz2chan(x[i]),x[i]);
			i++;
		}
		printf("\n");
		free(x);
	}else{
		printf("\nUnsuported channels\n");
	}
	
}


void print_supported_channels(void)
{
	uint8_t *x;
	int i;
	i=0;
	
	x=get_supported_channels();
	if (x!=NULL){
		printf("\nSupported channels:\n");
		while (x[i]!=0){
			printf("Channel: %u\n",x[i]);
			i++;
		}
		printf("\n");
		free(x);
	}else{
		printf("\nUnsuported channels\n");
	}
	
}


void print_supported_freq(void)
{
	uint16_t *x;
	int i;
	i=0;
	
	x=get_supported_freq();
	if (x!=NULL){
		printf("\nSupported freqency:\n");
		while (x[i]!=0){
			printf("Frequency: %u\n",x[i]);
			i++;
		}		printf("\n");
		free(x);
	}else{
		printf("\nUnsuported frequencies\n");
	}
	
}

//update number of packets
void ap_no_mk(struct access_point *ap, const struct pkg_util_info rd)
{
	if (ap==NULL){
		log_err(LEVEL10,(char *)"Null access point when updating number of recieved pkgs...");
		return;
	}

	ap->no_management+=(rd.no & NO_MANAGEMENT)>>7;
	ap->no_beacon+=(rd.no & NO_BEACON)>>6;
	ap->no_control+=(rd.no & NO_CONTROL)>>5;
	ap->no_data+=(rd.no & NO_DATA)>>4;

}	


//convert a chr represented in hexa into decimal 
char hexchr2dec(char chr)
{
	if (chr>='0' && chr<='9'){
		return chr-'0';
	}else{
		if (chr>='A' && chr<='F'){
			return chr-'A'+10;
		}else{
			if (chr>='a' && chr<='f'){
				return chr-'a'+10;
			}else{
				return -1;
			}
		}
	}
}
				
	
/*transforms mac from src (xx:xx:xx:xx:xx:xx) to dest[MAC_LEN]
INPUT:
	const char *src, (mac source given as xx:xx:xx:xx:xx:xx, where 0<=xx<=255 
OUTPUT:
	uint8_t dest[MAC_LEN], 
	
RETURN:
	-1 on error
	 0 on success
*/

char mac_parse(uint8_t dest[MAC_LEN],char *src)
{
	int i;
	uint8_t str2int;
	char *x;
	char c0;
	char c1;
	
	if (src==NULL){
		log_err(LEVEL10,(char *)"NULL src when trying to convert mac");
		return -1;
	}
	
	//check for size of mac with delimiters
	if (strlen(src)!=(2*MAC_LEN + (MAC_LEN-1))){
		log_err(LEVEL1,(char *)"Invalid mac length (3)");
	}
	
	x=strtok(src,":");
	for (i=0;i<MAC_LEN;i++){
		if (x!=NULL){
			c0=hexchr2dec(x[0]);
			c1=hexchr2dec(x[1]);
			if (c0==-1 || c1==-1){
				log_err(LEVEL1,(char *)"Invalid MAC address");
				return -1;
			}
			
			if (x[2]!='\0'){
				log_err(LEVEL1,(char *)"Invalid MAC address (2)");
				return -1;
			}
			
			
			str2int=(uint8_t)(c0<<4) | c1;
			

			dest[i]=str2int;
		}else{
			log_err(LEVEL1,(char *)"Invalid MAC. Length is different from %d",MAC_LEN);
			return -1;
		}
		x=strtok(NULL,":");
	}
	
	if (x!=NULL){
		log_err(LEVEL1,(char *)"Invalid MAC (2). Length is different from %d",MAC_LEN);
		return -1;
	}

	return 0;
}


void mac_init(uint8_t mac[MAC_LEN])
{
	memset(mac,'0',sizeof(uint8_t)*MAC_LEN);
}
	
void mac_cpy(uint8_t dest[MAC_LEN],const uint8_t src[MAC_LEN])
{
	memcpy(dest,src,sizeof(uint8_t)*MAC_LEN);
}


char mac_equal(const uint8_t dest[MAC_LEN],const uint8_t src[MAC_LEN])
{
	int i;
	for (i=0;i<MAC_LEN;i++){
		if (dest[i]!=src[i]){
			return 0;
		}
	}
	
	return 1;
}

//is timeout
//wpa2 arrives after wpa1!
int wpa_eapol_timeout(const struct wpa_eapol *wpa1, const struct wpa_eapol *wpa2)
{
	if (wpa1==NULL || wpa2==NULL){
		log_err(LEVEL2,(char *)"Invalid call of wpa_timeout");
		return -1;
	}
	
	//!bug 11 IEEE80211 specify just 100 ms for timeout we consider one second
	if ( (wpa2->last_seen - wpa1->last_seen) == 0 || (wpa2->last_seen - wpa1->last_seen) == 1){
		return 0;
	}else{
		return 1;
	}
}


//!not enough tested!
int wpa_eapol_update(struct access_point *ap,const struct wpa_eapol *wpa)
{
	if (ap==NULL){
		log_err(LEVEL2,(char *)"Null ap in wpa_update");
		return -1;
	}
	
	if (wpa==NULL){
		log_err(LEVEL2,(char *)"Null wpa in wpa_update");
		return -1;
	}
	
	//we are in state 1?
	if ( (wpa->state & EAPOL_STATE1) != 0 ){
				
		if (ap->wpa_new!=NULL){
			free(ap->wpa_new);
			//don't have to
			ap->wpa_new=NULL;
		}
				
		assert(ap->wpa_new=wpa_init());
		
		memcpy(ap->wpa_new,wpa,sizeof(struct wpa_eapol));
		ap->wpa_new->state=EAPOL_STATE1;
		
		return 1;
	}
			
	//we are in state 2?
	if ( (wpa->state & EAPOL_STATE2) != 0 ){
				
		if (ap->wpa_new==NULL){
			return 0;
		}
		
		//if we didn't recieve message 1 
		if ((ap->wpa_new->state & EAPOL_STATE1) == 0){
			return 0;
		}
		
		if (wpa_eapol_timeout(ap->wpa_new,wpa)!=0){
			free(ap->wpa_new);
			ap->wpa_new=NULL;
			return 0;
		}
		
		
		memcpy(ap->wpa_new->snonce,wpa->snonce,AUTH_NONCE_SIZE);
		memcpy(ap->wpa_new->eapol,wpa->eapol,AUTH_EAPOL_SIZE_MAX);
		memcpy(ap->wpa_new->stmac,wpa->stmac,HW_ADDR_SIZE);
		ap->wpa_new->eapol_size = wpa->eapol_size;
		memcpy(ap->wpa_new->mic,wpa->mic,AUTH_MIC_SIZE);
		
		ap->wpa_new->state=ap->wpa_new->state | EAPOL_STATE2;
		
		return 1;
	}

	//we are in state 3?
	if ( (wpa->state & EAPOL_STATE3) != 0){
	
		if (ap->wpa_new==NULL){
			return 0;
		}
		
		//if we didn't recieve message 1 and 2
		if ((ap->wpa_new->state & EAPOL_STATE2) == 0
			|| (ap->wpa_new->state & EAPOL_STATE1) == 0){
			return 0;
		}
		
		if (wpa_eapol_timeout(ap->wpa_new,wpa)!=0){
			return 0;
		}
		
		if (ap->wpa!=NULL){
			free(ap->wpa);
			ap->wpa=NULL;
		}
		
		assert(ap->wpa=ap->wpa_new);
		ap->wpa->state = ap->wpa->state | EAPOL_STATE3;
		
		ap->wpa_new=NULL;
		
		return 1;
	}
	
	if ((wpa->state & EAPOL_STATE4) != 0){

		//did we skip message 3?
		if (ap->wpa_new!=NULL){
			if ((ap->wpa_new->state & EAPOL_STATE2) == 0
				|| (ap->wpa_new->state & EAPOL_STATE1) == 0
				){
				return 0;
			}
			if (wpa_eapol_timeout(ap->wpa_new,wpa)!=0){
				return 0;
			}
			if (ap->wpa!=NULL){
				free(ap->wpa);
				ap->wpa=NULL;
			}
			ap->wpa_new->state = ap->wpa_new->state | EAPOL_STATE4;
			ap->wpa=ap->wpa_new;
			ap->wpa_new=NULL;
			return 1;
		}else{
			if (ap->wpa==NULL){
				return 0;
			}
			
			if ((ap->wpa->state & EAPOL_STATE2) == 0
				|| (ap->wpa->state & EAPOL_STATE1) == 0){
				return 0;
			}
			
			if (wpa_eapol_timeout(ap->wpa,wpa)!=0){
				return 0;
			}
			
			ap->wpa->state = ap->wpa->state | EAPOL_STATE4;
		
			return 1;
		}
	}
	
	//we should never be here
	return -1;
	
}
	
struct access_point *ap_add(struct access_point *last_ap, const struct pkg_util_info rd)
{
	struct access_point *ap_new;

	if (rd.bssid==NULL){
		log_err(LEVEL5,(char *)"Invalid bssid to add");
		return NULL;
	}

	ap_new=(struct access_point *)xmalloc(sizeof(struct access_point));
	
	memcpy(ap_new->bssid,rd.bssid,sizeof(u8)*sizeof(ap_new->bssid));

	if (strlen(rd.ssid)<IEEE802_INF_ELEMENT_SSID_MAX_LEN){
		ap_new->ssid=(char *)xmalloc(sizeof(char)*(strlen(rd.ssid)+1));
		memcpy(ap_new->ssid,rd.ssid,sizeof(char)*strlen(rd.ssid));
		ap_new->ssid[strlen(rd.ssid)]='\0';
	}else{
		ap_new->ssid=NULL;
	}
	

	ap_new->max_rate=rd.max_rate;
	
	//bsstime=NULL;
	
	assert(ap_new->fseen=rd.seen);	
	assert(ap_new->lseen=rd.seen);	
	
	ap_new->no_clients=0;
	ap_new->clients=NULL;
	
	
//!TODO who is type?
//	ap_new->type=-1;
	
	//if (ap_new->channel==0)
	ap_new->channel=rd.channel;
	
	ap_new->signal_power=rd.signal;
	ap_new->signal_noise=rd.noise;


//	ap_new->privacy=-1;
//	ap_new->encrypted=-1;
		
	ap_new->no_pkg=0;
	ap_new->no_beacon=0;
	ap_new->no_management=0;
	ap_new->no_data=0;
	ap_new->no_control=0;

	//update number of packets
	ap_no_mk(ap_new,rd);
	
	ap_new->cipher=rd.cipher;
	ap_new->auth=rd.auth;
	
	
	
	ap_new->wpa=NULL;
	ap_new->wpa_new=NULL;
	
	if (rd.wpa!=NULL)
		wpa_eapol_update(ap_new,rd.wpa);
	
	
	
	ap_new->prev=last_ap;
	ap_new->next=NULL;
	if (last_ap!=NULL){
		ap_new->id=last_ap->id + 1;
		last_ap->next=ap_new;
	}else{
		ap_new->id=0;
	}
	//DO NOT ADD LINES AFTER THIS COMMENT  last_ap->next=ap_new; must be the last line (or else, multiple threads can cause problems)
	
	
	return ap_new;
}	
	

void ap_update(struct access_point *ap, const struct pkg_util_info rd)
{
	if (ap==NULL){
		log_err(LEVEL5,(char *)"Invalid ap to update");
		return ;
	}
		
	if (rd.bssid==NULL){
		log_err(LEVEL5,(char *)"Invalid bssid to update");
		return ;
	}
	
	if (bssid_equal(ap->bssid,rd.bssid)==0){
		log_err(LEVEL6,(char *)"Invalid ap to update (different bssid)");
		return ;
	}
	
	if (ap->ssid!=NULL){
		if (rd.ssid[0]!='\0'){
			//rd.ssid should be less than IEEE802_INF_ELEMENT_SSID_MAX_LEN
			if (strlen(ap->ssid)!=strlen(rd.ssid) || strncmp(ap->ssid,rd.ssid,strlen(ap->ssid))!=0){
				if (strlen(rd.ssid)<IEEE802_INF_ELEMENT_SSID_MAX_LEN){
					free(ap->ssid);
					ap->ssid=(char *)xmalloc(sizeof(char)*(strlen(rd.ssid)+1));
					memcpy(ap->ssid,rd.ssid,sizeof(char)*strlen(rd.ssid));
					ap->ssid[strlen(rd.ssid)]='\0';
				}else{
					log_err(LEVEL9,(char *)"packet ssid > SSID_MAX_LEN in ap_update");
					return ;
				}
			}
		}
	}else{
		if (strlen(rd.ssid)<IEEE802_INF_ELEMENT_SSID_MAX_LEN){
			ap->ssid=(char *)xmalloc(sizeof(char)*(strlen(rd.ssid)+1));
			memcpy(ap->ssid,rd.ssid,sizeof(char)*strlen(rd.ssid));
			ap->ssid[strlen(rd.ssid)]='\0';
		}else{
			log_err(LEVEL9,(char *)"packet ssid > SSID_MAX_LEN in ap_update (2)");
			return ;
		}
	}
	
	assert(ap->ssid);
	
	//update number of packets
	ap_no_mk(ap,rd);
	
	if ((rd.channel>>7==0 || ap->channel>>7>=1 || ap->channel==0) && (rd.channel!=0)){
		ap->channel=rd.channel;
	}
	
	ap->signal_power=rd.signal;
	ap->signal_noise=rd.noise;
	
	ap->cipher=ap->cipher | rd.cipher;
	ap->auth=ap->auth | rd.auth;
	
	if (rd.wpa!=NULL)
		wpa_eapol_update(ap,rd.wpa);
	
}


/*
Parser for radiotap header

INPUT: 
	const u_char *packet - the packet from the wlan interface
	uint32_t len	     - length of the packet
OUTPUT: 
	struct pkg_util_info rd - will fill some fields in the structure (eg. channel, signal, noise) 

RETURN: 
	on success: radiotype length
	on error  : 0
*/
uint16_t radiotap_get(struct pkg_util_info *rd,const u_char *packet,uint32_t len)
{
	struct ieee80211_radiotap_header *radiotap;
	struct ieee80211_radiotap_iterator iterator;
	
	radiotap=(struct ieee80211_radiotap_header *)packet;
	//dbg("header size:%ld", radiotap->it_len);

	if (radiotap->it_version>PKTHDR_RADIOTAP_VERSION){
		log_err(LEVEL7,(char *)"Unsuported version of radiotap");
		return 0;
	}
	
	if (radiotap->it_len<8 || radiotap->it_len>len){
		log_err(LEVEL7,(char *)"Invalid packet length");
		return 0;
	}
	
	ieee80211_radiotap_iterator_init(&iterator,radiotap,radiotap->it_len);
	
	while (ieee80211_radiotap_iterator_next(&iterator)>=0){
//		printf("index:%d val:%02x\n len:%d\n",iterator.this_arg_index,iterator.this_arg[0],iterator.max_length);
//		printf("sizeofchar:%d,u8:%d\n",sizeof(char),sizeof(u8));

//!TODO we should check also  IEEE80211_RADIOTAP_DB_ANTSIGNAL IEEE80211_RADIOTAP_DB_ANTNOISE
		switch (iterator.this_arg_index){    
			/*case IEEE80211_RADIOTAP_FLAGS:
				//rd.flags=iterator.this_arg;
				break;*/
			case IEEE80211_RADIOTAP_CHANNEL: 
				rd->channel=(uint8_t)ieee80211mhz2chan((uint32_t)((iterator.this_arg[1])*256+(iterator.this_arg[0]))) | 0x80;
				//rd->channel=0;
				break;
			case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
				rd->signal=(uint8_t)*iterator.this_arg-256;
				break;
			case IEEE80211_RADIOTAP_DBM_ANTNOISE:
				rd->noise=*iterator.this_arg-256;
				break;
		}				 
	}
	return radiotap->it_len;
}


/*set hardware address in rd structure

INPUT:
	u8 *src_addr  -  Source address 
	u8 *dst_addr  -  Destination address
	u8 *bssid_addr-  Address of the bssid
OUTPUT: 
	struct pkg_util_info rd - informations parsed from packet

RETURN: void
*/
void rd_addr_set(struct pkg_util_info *rd,u8 *src_addr, u8 *dst_addr, u8 *bssid_addr)
{
	//printf("SIZEOF:%d (must be 6)\n",sizeof(rd->da));

	if (src_addr!=NULL){
		memcpy(rd->sa,src_addr,sizeof(u8)*sizeof(rd->sa));
	}
	
	if (dst_addr!=NULL){
		memcpy(rd->da,dst_addr,sizeof(u8)*sizeof(rd->da));
	}
	
	if (bssid_addr!=NULL){
		memcpy(rd->bssid,bssid_addr,sizeof(u8)*sizeof(rd->bssid));
	}
//	dbg_mac("dbg SA",rd->sa);
//	dbg_mac("dbg DA",rd->da);
//	dbg_mac("dbg BSSID",rd->bssid);
}


/*
parser for IEEE802.11 CONTROL FRAMES 

INPUT - OUTPUT:
	struct pkg_util_info rd - informations parsed from packet

OUTPUT:
	int *frame_body - 1 if frame has body 
			- 0 if frame has no boddy 

RETURN:
	on success: frame header length;
	on error  : -1
*/
int do_frame_control(struct pkg_util_info *rd, struct ieee80211_frame *f80211,int *frame_body)
{

	int fc_len;

	*frame_body=0;
	fc_len=-1;
	
	switch (rd->type_subtype){
		case IEEE80211_FRAME_CONTROL_RST:
			fc_len=IEEE80211_FRAME_CONTROL_RST_H_SIZE;
			rd_addr_set(rd,f80211->addr2,f80211->addr1,NULL);
			//RA=address1;
			//TA=address2
			break;
		case IEEE80211_FRAME_CONTROL_CST:
			fc_len=IEEE80211_FRAME_CONTROL_CST_H_SIZE;
			rd_addr_set(rd,NULL,f80211->addr1,NULL);
			//RA=address1;
			break;
		case IEEE80211_FRAME_CONTROL_ACK:
			fc_len=IEEE80211_FRAME_CONTROL_ACK_H_SIZE;
			rd_addr_set(rd,NULL,f80211->addr1,NULL);
			//RA=address1;
			break;
		case IEEE80211_FRAME_CONTROL_PSPOLL:
			fc_len=IEEE80211_FRAME_CONTROL_PSPOLL_H_SIZE;
			rd_addr_set(rd,f80211->addr2,f80211->addr1,f80211->addr1);
			//RA=address1; (BSSID)
			//RA=address1;
			//TA=address2;
			break;
		case IEEE80211_FRAME_CONTROL_CFEND:
			fc_len=IEEE80211_FRAME_CONTROL_CFEND_H_SIZE;
			rd_addr_set(rd,f80211->addr2,f80211->addr1,f80211->addr2);
			//RA=address1
			//TA=address2 (BSSID)
			//TA=address2 (BSSID)
			break;
		case IEEE80211_FRAME_CONTROL_CFEND_CFACK:		
			fc_len=IEEE80211_FRAME_CONTROL_CFEND_CFACK_H_SIZE;
			rd_addr_set(rd,f80211->addr2,f80211->addr1,f80211->addr2);
			//RA=address1;
			//TA=address2; (BSSID)
			break;
		case IEEE80211_FRAME_CONTROL_BLOCKACKREQ:
			fc_len=IEEE80211_FRAME_CONTROL_BLOCKACKREQ_H_SIZE;
			rd_addr_set(rd,f80211->addr2,f80211->addr1,NULL);
			//RA=address1;
			//TA=address2;
			//still there are 4 octets with: bar control (2 octets) and Block ack starting sequence control (2 octets)
			break;
		case IEEE80211_FRAME_CONTROL_BLOCKACK:
			fc_len=IEEE80211_FRAME_CONTROL_BLOCKACK_H_SIZE;
			rd_addr_set(rd,f80211->addr2,f80211->addr1,NULL);
			//RA=address1;
			//TA=address2;
			//still there are 4+128 octets with: ba control (2 octets), Block ack starting sequence control (2 octets) and block ack bitmap (128 octets)
			break;
		default:
			log_err(LEVEL4,(char *)"Invalid subtype for CONTROL FRAME");
			return -1;
	}
	return fc_len;
}



//check if data frame is a eapol
//if yes it will be stored in rd
int data_frame_try_snap(struct pkg_util_info *rd, const u_char *data_packet, unsigned int data_length)
{
	struct llc_snap *snap;
		
	struct auth_80211 *auth;

	if (data_length<LLC_SNAP_SIZE){
		return -1;
	}
	
	if (data_packet==NULL){
		return -1;
	}
	
	
	snap=(struct llc_snap *)data_packet;
	
	
//	if (snap->dsap==0xaa){
		//dbg("ok1 %02x",snap->dsap);
	//}
	
	//IEEE802 2001 dsap(aa) ssap(aa) ctl(03) oui(00-00-00) snap_type=(888e)
	if (snap->dsap==0xaa && snap->ssap==0xaa && snap->ctl==0x03 
//?		&& snap->oui[0]==0x00 && snap->oui[1]==0x00 && snap->oui[2]==0x00
		&& snap->type_hi==0x88 && snap->type_low==0x8e){
		//dbg("OK snap");
		data_packet = data_packet + LLC_SNAP_SIZE;
		data_length = data_length - LLC_SNAP_SIZE;
		
		if (data_length<sizeof(struct auth_80211)){
			log_err(LEVEL6,(char *)"Malformated pkg? Sizeof structure auth is smaller than the length of the packet");
			return -1;
		}
		
		auth=(struct auth_80211 *)data_packet;
		
		//xxx. version 2 not enough tested!!!
		if (auth->version != AUTH_SUPPORTED_VERSION1 && auth->version != AUTH_SUPPORTED_VERSION2){
			log_err(LEVEL10,(char *)"Unsuported EAPOL. Auth version (%02x) not supported",auth->version);
			return -1;
		}
		
//BUG 17		
//AUTH version 2 not tested!
		if (auth->version == AUTH_SUPPORTED_VERSION2){
			log_err(LEVEL10,(char *)"Auth version 2 not tested. Crack may not work.");
		}
		
		if (auth->type != AUTH_SUPPORTED_TYPE){
			log_err(LEVEL10,(char *)"Unsuported type");
			return -1;
		}

		
		//alocate space for wpa
		rd->wpa = wpa_init();
		
		
		rd->wpa->last_seen=rd->seen;
		rd->wpa->version=auth->key_info_low & AUTH_EAPOL_PARSE_KEY_LOW_INFO_VERSION;
		
		
		//message1: pairwise=1 install=0   ack=1 mic=0 secure=0 error=0
		//message2: pairwise=1 install=0   ack=0 mic=1 secure=0 error=0
		//mesaage3: pairwise=1 install=0/1 ack=1 mic=1 secure=1 error=0
		//message4: pairwise=1 install=0   ack=0 mic=1 secure=1 error=0
		//dbg_hex("data:",data_packet,data_length);
		//printf("key: %02x %02x",(auth->key_info_hi),(auth->key_info_low));
		if ( (auth->key_info_low & AUTH_EAPOL_PARSE_KEY_LOW_TYPE) != 0 
			&& (auth->key_info_hi & AUTH_EAPOL_PARSE_KEY_HI_ERROR) == 0 ){
			

			
			if ( (auth->key_info_hi & AUTH_EAPOL_PARSE_KEY_HI_MIC)==0 ){
				//dbg("1 ok: hi:%02x low:%02x",auth->key_info_hi,auth->key_info_low);	
				//handshake: message 1
				
				//ack=1 && secure=0
				if ( (auth->key_info_low & AUTH_EAPOL_PARSE_KEY_LOW_ACK) != 0 
					&& (auth->key_info_hi & AUTH_EAPOL_PARSE_KEY_HI_SECURE) ==0 ){
					
					memcpy(rd->wpa->anonce,auth->nonce,AUTH_NONCE_SIZE);
					
					rd->wpa->state=EAPOL_STATE1;
				}else{
					log_err(LEVEL6,(char *)"Malformated packet: Invalid EAPOL");
					free(rd->wpa);
					rd->wpa=NULL;
					return -1;
				}
			}else{
					//dbg("msg2 key: hi:%02x low:%02x",auth->key_info_hi,auth->key_info_low);	
				//ack=0 && secure=0
				if ( (auth->key_info_hi & AUTH_EAPOL_PARSE_KEY_HI_SECURE) ==0 ){
					
			//		dbg("key: hi:%02x low:%02x",auth->key_info_hi,auth->key_info_low);
					//handshake: message 2 
					if ((auth->key_info_low & AUTH_EAPOL_PARSE_KEY_LOW_ACK) == 0 ){
						
						//bug for some equipaments that didn't hear about IEEE802.11
						//if (last_state!=EAPOL_STATE1){
						//	log_err(LEVEL6,(char *)"Malformated packet, or partial transmission : Invalid EAPOL");
						//	free(rd->wpa);
						//	rd->wpa=NULL;
						//	return -1;
							
						//}
						
					//	dbg("auth:%02x",auth->replay_counter[0]);
					//	dbg("auth7:%02x",auth->replay_counter[7]);
						//!TODO ATENTION ON LITTLE INDIAN/BIG INDIAN!!!!
						//BUG15 little/big indian
						//for those that does not support propper IEEE 802.11
						if (auth->replay_counter[7]!=0x01){
								log_err(LEVEL6,(char *)"Malformated packet, or partial transmission : Invalid EAPOL");
								free(rd->wpa);
								rd->wpa=NULL;
								return -1;
						}
						
						rd->wpa->eapol_size=(auth->length_hi << 8) | auth->length_low;
		
						//key length does not include fields before it
						rd->wpa->eapol_size = rd->wpa->eapol_size + AUTH_LENGTH_OFFSET;
		
						
						if (rd->wpa->eapol_size>AUTH_EAPOL_SIZE_MAX){
							log_err(LEVEL7,(char *)"Invalid size of eapol.");
							free(rd->wpa);
							rd->wpa=NULL;
							return -1;
						}
						
						if (rd->wpa->eapol_size<AUTH_MIC_OFFSET+AUTH_MIC_SIZE){
							log_err(LEVEL7,(char *)"Invalid size of eapol (2)");
							free(rd->wpa);
							rd->wpa=NULL;
							return -1;
						}

						memcpy(rd->wpa->snonce,auth->nonce,AUTH_NONCE_SIZE);
						rd->wpa->state = rd->wpa->state | EAPOL_STATE2;

						memcpy(rd->wpa->stmac,rd->sa,HW_ADDR_SIZE);
						
						memcpy(rd->wpa->eapol,data_packet,rd->wpa->eapol_size);
						
						memset(rd->wpa->eapol + AUTH_MIC_OFFSET,0,AUTH_MIC_SIZE);
						
						memcpy(rd->wpa->mic,auth->wpa_key_mic,AUTH_MIC_SIZE);
						
						//pr("EAPOL SUS:",rd->wpa->eapol,rd->wpa->eapol_size);
						
					}else{
						log_err(LEVEL6,(char *)"Malformated packet: Invalid EAPOL (2).");
						free(rd->wpa);
						rd->wpa=NULL;
						return -1;
					}
					
					
				} else {
					//handshake: message 3 or 4
					if ( (auth->key_info_low & AUTH_EAPOL_PARSE_KEY_LOW_ACK) != 0 ){
						rd->wpa->state = rd->wpa->state | EAPOL_STATE3;
					}else{
						rd->wpa->state = rd->wpa->state | EAPOL_STATE4;
					}
				}
			}
		}

		
		return 0;
	}
	return -1;
	
}
/*
parser for IEEE802.11 DATA FRAMES 

INPUT - OUTPUT:
	struct pkg_util_info rd - informations parsed from packet



RETURN:
	on success: 0 
	            1 
		
	on error  : -1
	
BUGS:
	should check rd.flag_ds=3
	ADDR4 not saved!
*/
//!TODO! see what to return
int do_frame_data(struct pkg_util_info *rd, struct ieee80211_frame *f80211, const u_char *data_packet, unsigned int data_length)
{
	unsigned int fc_len;

	
	/*when type is DATA
	+---+---+------------+------------+-------+-------+
	|Frm|To |  Address1  | Address2   | Addr. | Addr. |
	|DS |DS |	     |            |   3   |   4   |
	+---+---+------------+------------+-------+-------+
	| 0 | 0 | RA = DA    | TA = SA    | BSSID | N/A   |
	| 0 | 1 | RA = BSSID | TA = SA    | DA    | N/A   |
	| 1 | 0 | RA = DA    | TA = BSSID | SA    | N/A   |
	| 1 | 1 | RA 	     | TA 	  | DA    | SA    |
	+---+---+------------+------------+-------+-------+*/
	fc_len=0;
	switch (rd->flag_ds){
		case 0:
			//RA=DA=address1;
			//TA=SA=address2;
			//BSSID=address3;
			rd_addr_set(rd,f80211->addr2,f80211->addr1,f80211->addr3);
			fc_len=IEEE80211_FRAME_DATA_NO_ADDR4_H_SIZE;
			break;
		case 1:
			//RA=BSSID=address1;
			//TA=SA=address2;
			//DA=address3;
			rd_addr_set(rd,f80211->addr2,f80211->addr3,f80211->addr1);
			fc_len=IEEE80211_FRAME_DATA_NO_ADDR4_H_SIZE;
			break;
		case 2:
			//RA=DA=address1;
			//TA=BSSID=adress2;
			//SA=address3;
			rd_addr_set(rd,f80211->addr3,f80211->addr1,f80211->addr2);
			fc_len=IEEE80211_FRAME_DATA_NO_ADDR4_H_SIZE;
			break;

		case 3:
			//RA=address1;
			//TA=address2;
			//DA=address3;
			//here is addr4
//!BUG 1 (marked as) 
//!TODO Maybe a bug?!? here?! Should check!
//! i think that TA and RA are both BSSID!?
			rd_addr_set(rd,f80211->addr1,f80211->addr3,f80211->addr2);
			fc_len=IEEE80211_FRAME_DATA_W_ADDR4_H_SIZE;
			break;
		default:
			log_err(LEVEL4,(char *)"BUG FOUND (frame_control DS>3)");
			return -1;
	}
	
	if ( fc_len > data_length ){
		log_err(LEVEL6,(char *)"Malformated data pkg: length too big");
		return -1;
	}
	
	data_packet = data_packet + fc_len;
	data_length = data_length - fc_len;
	
	switch (rd->type_subtype){
		case IEEE80211_FRAME_DATA_DATA:
			//*frame_body=1;
			
			if (data_frame_try_snap(rd,data_packet,data_length)!=0){
				return 1;
			}
			break;
		case IEEE80211_FRAME_DATA_DATA_ACK:
		case IEEE80211_FRAME_DATA_DATA_CFPOOL:
		case IEEE80211_FRAME_DATA_DATA_CFACK_CFPOLL:
			///*frame_body=1;
			break;
		case IEEE80211_FRAME_DATA_NULL:
		case IEEE80211_FRAME_DATA_CFACK:
		case IEEE80211_FRAME_DATA_CFOLL:
		case IEEE80211_FRAME_DATA_CFACK_CFPOLL:
			//*frame_body=0;
			break;
		case IEEE80211_FRAME_DATA_QOS_DATA:
			
			if (data_length-sizeof(uint8_t)*2 > 0){
				data_packet = data_packet+sizeof(uint8_t)*2;
				data_length= data_length-sizeof(uint8_t)*2;
				if (data_frame_try_snap(rd,data_packet,data_length)!=0){
					return 1;
				}
			}
			fc_len=IEEE80211_FRAME_DATA_W_QOS_H_SIZE;
			break;
		case IEEE80211_FRAME_DATA_QOS_DATA_CFACK:
		case IEEE80211_FRAME_DATA_QOS_DATA_CFPOLL:
		case IEEE80211_FRAME_DATA_QOS_DATA_CFACK_CFPOLL:
			//*frame_body=1;
			fc_len=IEEE80211_FRAME_DATA_W_QOS_H_SIZE;
			break;
		case IEEE80211_FRAME_DATA_QOS_NULL:
		case IEEE80211_FRAME_DATA_QOS_CFPOLL:
		case IEEE80211_FRAME_DATA_QOS_CFACK_CFPOLL:
			//*frame_body=0;
			fc_len=IEEE80211_FRAME_DATA_W_QOS_H_SIZE;
			break;
		default:
			log_err(LEVEL4,(char *)"Invalid subtype for DATA FRAME");
			return -1;
	}
	
	
	
	
	//return fc_len;
	return 0;
}


/*init a structure used for parsing management frames
INPUT: 
	const u_char *frame_body  - management frame body
	unsigned int frame_length - length of management frame_body
OUTPUT:
	struct information_element *inf_element - init for all structure elements
*/ 
void management_element_init(struct information_element *inf_element,const u_char *frame_body,unsigned int frame_length)
{
	
	inf_element->frame_body=frame_body;
	inf_element->frame_length=frame_length;
	inf_element->crt_index=0;
	inf_element->tag_number=-1;
	inf_element->tag_len=0;
	inf_element->tag_info=NULL;
	

}

/* 
ATTENTION:
	inf_element must be first initialised using management_element_init(...)
INPUT-OUTPUT: 
	struct information_element *inf_element -  srtucture which contains information parsed from management frames 
RETURN:
	on success: 0 if all elements were parsed
		    tag length if there are other elements to parse
	on error  : -1
*/
int management_element_parse(struct information_element *inf_element)
{
	
	if (inf_element->frame_length==0){
		log_err(LEVEL7,(char *)"Malformated packet: Zero length!");
		return -1;
	}
	
	if (inf_element->frame_body==NULL){
		log_err(LEVEL7,(char *)"Malformated packet: NULL information element!");
		return -1;
	}
	
	//we parsed all data in the packet
	if (inf_element->crt_index>=inf_element->frame_length){
		return 0;
	}
	
	/*!!!!!!!!!!!!!!!!!!!!XXXXX error on 64 bits*/
	//!BUG 9 PROBLEM IN 64 bits architectures
	if (sizeof(inf_element->tag_number) + sizeof(inf_element->tag_len) + inf_element->crt_index >= inf_element->frame_length ){
		//printf("crt_index: %d frame_length: %d",inf_element->crt_index,inf_element->frame_length);
		log_err(LEVEL8,(char *)"Malformated packet[element]: Invalid length of the packet");
		return -1;
	}
	
 	inf_element->tag_number=(u8)*inf_element->frame_body;
	inf_element->tag_len=(u8) *(inf_element->frame_body+sizeof(inf_element->tag_number));
	
	/*!!!!!!!!!!!!!!!!!!!!XXXXX error on 64 bits*/
	//!BUG 9 PROBLEM IN 64 bits architectures
	if (inf_element->crt_index + sizeof(inf_element->tag_number) + sizeof(inf_element->tag_len) + inf_element->tag_len > inf_element->frame_length){
		log_err(LEVEL8,(char *)"Malformated packet[element]: Invalid length of the packet (2)");
		return -1;
	}


	inf_element->tag_info=(u8 *)(inf_element->frame_body+sizeof(inf_element->tag_number) + sizeof(inf_element->tag_len));
	inf_element->frame_body=inf_element->frame_body+sizeof(inf_element->tag_number) + sizeof(inf_element->tag_len)+inf_element->tag_len;
	inf_element->crt_index+=sizeof(inf_element->tag_number) + sizeof(inf_element->tag_len) + inf_element->tag_len;
	
	return inf_element->tag_len;
}



uint16_t cipher_decoder_rsn(uint32_t cipher_suite)
{
	uint16_t x;
	x=0;
	switch(cipher_suite){
		case IEEE802_INF_ELEMENT_RSN_CIPHER_GROUP:
		//! TODO implement GROUP CIPHER SUITE!!!!
			x = x | CIPHER_GRP;
		break;
		case IEEE802_INF_ELEMENT_RSN_CIPHER_WEP40:
			x = x | CIPHER_WEP40;
		break;
		case IEEE802_INF_ELEMENT_RSN_CIPHER_TKIP:
			x = x | CIPHER_TKIP;
		break;
		case IEEE802_INF_ELEMENT_RSN_CIPHER_CCMP:
			x = x | CIPHER_CCMP;
		break;
		case IEEE802_INF_ELEMENT_RSN_CIPHER_WEP104:
			x = x | CIPHER_WEP104;
		break;
		default:
			x = x | CIPHER_PROPRIETARY;
		break;
	}
	return x;

}

uint8_t akm_decoder_rsn(uint32_t akm_suite)
{
	uint8_t x;
	
	x=0;
	switch (akm_suite){
		case IEEE802_INF_ELEMENT_RSN_AKM_RSNA:
			x = x | AUTH_RSNA;
			break;
		case IEEE802_INF_ELEMENT_RSN_AKM_PSK:
			x = x | AUTH_PSK;
			break;
		default:
			x = x | AUTH_PROPRIETARY;
			break;
	}
	
	return x;
}




uint16_t cipher_decoder_vendor(uint32_t cipher_suite)
{
	uint16_t x;
	x=0;
	switch(cipher_suite){
		case IEEE802_INF_ELEMENT_VENDOR_CIPHER_GROUP:
			x = x | CIPHER_GRP;
		break;
		case IEEE802_INF_ELEMENT_VENDOR_CIPHER_WEP40:
			x = x | CIPHER_WEP40;
		break;
		case IEEE802_INF_ELEMENT_VENDOR_CIPHER_TKIP:
			x = x | CIPHER_TKIP;
		break;
		case IEEE802_INF_ELEMENT_VENDOR_CIPHER_CCMP:
			x = x | CIPHER_CCMP;
		break;
		case IEEE802_INF_ELEMENT_VENDOR_CIPHER_WEP104:
			x = x | CIPHER_WEP104;
		break;
		default:
			x = x | CIPHER_PROPRIETARY;
		break;
	}
	return x;

}

uint8_t akm_decoder_vendor(uint32_t akm_suite)
{
	uint8_t x;
	
	x=0;
	switch (akm_suite){
		case IEEE802_INF_ELEMENT_VENDOR_AKM_RSNA:
			x = x | AUTH_RSNA;
			break;
		case IEEE802_INF_ELEMENT_VENDOR_AKM_PSK:
			x = x | AUTH_PSK;
			break;
		default:
			x = x | AUTH_PROPRIETARY;
			break;
	}
	
	return x;
}


char do_cipher_decode(uint16_t (*cipher_decoder) (uint32_t ),uint8_t (*akm_decoder)(uint32_t ), struct pkg_util_info *rd,const u_char *elem_info,unsigned int elem_len)
{

	uint16_t version;
	uint32_t cipher_suite;
	uint16_t pairwise_count;
	uint16_t akm_count;
	uint32_t akm_suite;
	
	//uint16_t enc;
	
	//enc=0;
	//auth=0;
	
	//dbg_hex("PKG:",elem_info,elem_len);
	
	if (elem_len<sizeof(version)){
		log_err(LEVEL6,(char *)"Malformated elem_info: invalid length in ciper_decode");
		return -1;
	}
	
	//printf("elem_len:%x\n",elem_len);
	//ALWAYS TRUE


	version=(uint16_t)(elem_info[0]<<8 |  elem_info[1]);
//BUG 7 this function decode cipher from rsn element and from vendor element 
//	we just check for vendor version 
	//just version 1 at this time
	if (version!=IEEE802_INF_ELEMENT_RSN_VERSION){
		log_err(LEVEL10,(char *)"Unsuported version of ciper_decode");
		return -1;
	}
	elem_info+=sizeof(version);
	elem_len-=sizeof(version);

	//cipher suite
	if (elem_len>=sizeof(cipher_suite)){
		cipher_suite=(uint32_t)(elem_info[0]<<24 | elem_info[1]<<16 | elem_info[2]<<8 | elem_info[3]);
		//memcpy(&cipher_suite,elem_info,sizeof(cipher_suite));
		//printf("CHP:%",cipher_suite);
		//dbg_bin("CHP:",cipher_suite,sizeof(cipher_suite));
		//exit(1);

		rd->cipher=rd->cipher | (*cipher_decoder)(cipher_suite);
		
		elem_info+=sizeof(cipher_suite);
		elem_len-=sizeof(cipher_suite);
		
	}else{
		return 0;
	}
	
	//dbg_hex("PKG:",elem_info,elem_len);
	//pairwise count
	if (elem_len>=sizeof(pairwise_count)){
		pairwise_count=(uint16_t)(elem_info[1]<<8 | elem_info[0]);
		if (pairwise_count==0){
			log_err(LEVEL6,(char *)"Malformated packet. ciper_decode information element has pairwise count 0");
			return -1;
		}
		elem_info+=sizeof(pairwise_count);
		elem_len-=sizeof(pairwise_count);
	}else{
		return 0;
	}
	
	
	//printf("cnt:%d\n",pairwise_count);
	//pairwise list
	if (elem_len>=pairwise_count*4){
		//util info but ignoring!
		
		while (pairwise_count>0){
			cipher_suite=(uint32_t)(elem_info[0]<<24 | elem_info[1]<<16 | elem_info[2]<<8 | elem_info[3]);
		
			rd->cipher=rd->cipher | (*cipher_decoder)(cipher_suite);
			
			elem_info+=sizeof(cipher_suite);
			elem_len-=sizeof(cipher_suite);
			
			pairwise_count--;
		}
		
		//elem_info+=pairwise_count*4;
		//elem_len-=pairwise_count*4;
	}else{
		log_err(LEVEL6,(char *)"Malformated packet. ciper_decode information element has invalid pairwise count (>pkg_len)");
		return -1;
	}
	
	
	//akm_count
	if (elem_len>=sizeof(akm_count)){
		akm_count=(uint16_t)(elem_info[1]<<8 | elem_info[0]);
		if (akm_count==0){
			log_err(LEVEL6,(char *)"Malformated packet. ciper_decode information element has akm count 0");
			return -1;
		}
		elem_info+=sizeof(akm_count);
		elem_len+=sizeof(akm_count);
	}else{
		return 0;
	}
	
	if (elem_len>=akm_count*4){
		
		
		while (akm_count > 0){

			akm_suite=(uint32_t)(elem_info[0]<<24 | elem_info[1]<<16 | elem_info[2]<<8 | elem_info[3]);
			rd->auth = rd->auth | (*akm_decoder)(akm_suite);
			
			elem_info+=sizeof(akm_suite);
			elem_len+=sizeof(akm_suite);
			akm_count--;
		}
			
		//elem_info+=akm_count*4;
		//elem_len-=akm_count*4;
	}else{
		log_err(LEVEL6,(char *)"Malformated packet. ciper_decode information element has invalid akm count (>pkg_len)");
		return -1;
	}
	
	return 0;

}

//just RSN ELEM
//-1 on error 
//0 on success
char do_information_element_RSN(struct pkg_util_info *rd,const u_char *elem_info,unsigned int elem_len)
{
	char ret;
	ret = do_cipher_decode(cipher_decoder_rsn, akm_decoder_rsn, rd, elem_info, elem_len);
	if (ret!=0){
		log_err(LEVEL6,(char *)"Can't parse RSN information element (%d)",ret);
	}
	return ret;
}


//check the WPA availability
//same as RSN but it is in vendor information element
char do_information_element_vendor_wpa(struct pkg_util_info *rd,const u_char *elem_info,unsigned int elem_len)
{
	char ret;
	ret = do_cipher_decode(cipher_decoder_vendor, akm_decoder_vendor, rd, elem_info, elem_len);
	if (ret!=0){
		log_err(LEVEL6,(char *)"Can't parse VENDOR information element (cipher)");
	}
	return ret;
}



	
//-1 on error
//0 if no information were parsed
//1 if informations were parsed
char do_information_element_vendor(struct pkg_util_info *rd,const u_char *elem_info,unsigned int elem_len)
{
	uint32_t oui;
	
	if (elem_len<sizeof(IEEE802_INF_ELEMENT_VENDOR_OUI)){
		log_err(LEVEL10,(char *)"Small inf element %u",sizeof(IEEE802_INF_ELEMENT_VENDOR_OUI));
		return -1;
	}
	
	oui=(uint32_t)(elem_info[0]<<24 | elem_info[1]<<16 | elem_info[2]<<8 | elem_info[3]);
	if (oui==IEEE802_INF_ELEMENT_VENDOR_OUI){
		elem_info+=sizeof(IEEE802_INF_ELEMENT_VENDOR_OUI);
		elem_len-=sizeof(IEEE802_INF_ELEMENT_VENDOR_OUI);
		
		if (do_information_element_vendor_wpa(rd,elem_info,elem_len)==0){
			return 1;
		}else{
			return -1;
		}
	}else{
		return 0;
	}
}


void do_frame_management_beacon(struct pkg_util_info *rd, struct ieee80211_frame *f80211, const u_char *beacon_packet,unsigned int beacon_length)
{
	struct information_element inf_element;
	uint16_t capability;
	
	//printf("Beacon frame\n");
	if (BEACON_FIXED_PARAM_LEN>beacon_length){
		log_err(LEVEL6,(char *)"Malformated pkg: Invalid beacon length");
		return;
	}
	
	
	//first 10 bytes are timestamp and beacon interval
	capability =(uint16_t)  beacon_packet[11]<<8 | beacon_packet[10];
	//printf("\n%04x\n",capability);
	
	
	if ((capability&CAPABILITY_WEP)!=0){
		rd->cipher=rd->cipher | CIPHER_WEP;
	}else{
		rd->cipher=CIPHER_OPN;
	}
	
	beacon_packet=beacon_packet+BEACON_FIXED_PARAM_LEN;
	beacon_length=beacon_length-BEACON_FIXED_PARAM_LEN;
	
	
//	dbg("frame_length:%u",beacon_length);
//	dbg_hex("MANAGEMENT PACKET:",beacon_packet,beacon_length);
	
	management_element_init(&inf_element,beacon_packet,beacon_length);
	
	while(management_element_parse(&inf_element)>0){
		
	
		//printf("TAG_NUMBER:%d\n",inf_element.tag_number);
		//printf("TAG_LENGTH:%d",inf_element.tag_len);
		//dbg_hex("TAG_VALUE",inf_element.tag_info,inf_element.tag_len);
		
		//ELEMENT ID
		switch (inf_element.tag_number){
			
			case IEEE802_INF_ELEMENT_SSID:
				if (inf_element.tag_len<=IEEE802_INF_ELEMENT_SSID_MAX_LEN){
					if (inf_element.tag_len>0){
						strncpy(rd->ssid,(char *)inf_element.tag_info,inf_element.tag_len);
						rd->ssid[inf_element.tag_len]='\0';
					}else{
						rd->ssid[0]='\0';
					}
				}else{
					log_err(LEVEL8,(char *)"Malformated pkg. Invalid ssid");
					rd->ssid[0]='\0';
				}
				break;
				
			case  IEEE802_INF_ELEMENT_DS:
				if (inf_element.tag_len<=IEEE802_INF_ELEMENT_DS_MAX_LEN && inf_element.tag_len>0){
					rd->channel=(uint8_t)*inf_element.tag_info;
				}else{
					log_err(LEVEL8,(char *)"Malformated pkg. Invalid DS");
				}
				break;
			case IEEE802_INF_ELEMENT_RSN:
				do_information_element_RSN(rd,inf_element.tag_info,inf_element.tag_len);
				break;
			case IEEE802_INF_ELEMENT_VENDOR:
				do_information_element_vendor(rd,inf_element.tag_info,inf_element.tag_len);
				break;
		}
	}
}


/*
parser for IEEE802.11 MANAGEMENT FRAMES 

INPUT
	const u_char *management_packet - management packet (no radiotap)
	unsigned int pkg_length		- length of management packet

INPUT - OUTPUT:
	struct pkg_util_info rd - informations parsed from packet

OUTPUT:
	int *frame_body - 1 if frame has body 
			- 0 if frame has no boddy 

RETURN:
	on success: frame header length;
	on error  : -1
*/

int do_frame_management(struct pkg_util_info *rd, struct ieee80211_frame *f80211, const u_char *management_packet,unsigned int pkg_length)
{
	int fc_len;
	
	fc_len=-1;
	//ieee80211_frame_body_start=-1;
	
	//*frame_body=1;
	switch (rd->type_subtype){
		case IEEE80211_FRAME_MANAGEMENT_BEACON:
			fc_len=IEEE80211_FRAME_MANAGEMENT_H_SIZE;
			rd_addr_set(rd,f80211->addr2,f80211->addr1,f80211->addr3);
			//DA=Address1;
			//SA=address2;
			//BSSID=address3;
			if (IEEE80211_FRAME_MANAGEMENT_H_SIZE>pkg_length){
				log_err(LEVEL5,(char *)"Malformated packet: invalid length of management packet");
				return -1;
			}
			do_frame_management_beacon(rd,f80211,(management_packet+IEEE80211_FRAME_MANAGEMENT_H_SIZE),pkg_length-IEEE80211_FRAME_MANAGEMENT_H_SIZE);
			rd->no=rd->no | NO_BEACON;
			break;
		case IEEE80211_FRAME_MANAGEMENT_ASSOS_REQ:
		case IEEE80211_FRAME_MANAGEMENT_ASSOS_RESP:
		case IEEE80211_FRAME_MANAGEMENT_REASSOS_REQ:
		case IEEE80211_FRAME_MANAGEMENT_REASSOS_RESP:
		case IEEE80211_FRAME_MANAGEMENT_PROBE_REQ:
		case IEEE80211_FRAME_MANAGEMENT_PROBE_RESP:
		case IEEE80211_FRAME_MANAGEMENT_ATIM:
		case IEEE80211_FRAME_MANAGEMENT_DISSASOC:
		case IEEE80211_FRAME_MANAGEMENT_AUTH:
		case IEEE80211_FRAME_MANAGEMENT_DEAUTH:
		case IEEE80211_FRAME_MANAGEMENT_ACTION:
			fc_len=IEEE80211_FRAME_MANAGEMENT_H_SIZE;
			rd_addr_set(rd,f80211->addr2,f80211->addr1,f80211->addr3);
			//DA=Address1;
			//SA=address2;
			//BSSID=address3;
			break;
		default:
			log_err(LEVEL4,(char *)"Invalid subtype for DATA MANAGEMENT");
			return -1;
	}
	
	return fc_len;
}



/*
Main function for packet parsing

INPUT:


OUTPUT:
MODIFY OF GLOBAL VARIABLES:


*/

void do_pkg(const struct pcap_pkthdr *header, const u_char *packet,int radiotap_exist,int is_offline)
{

	struct pkg_util_info rd;
	struct ieee80211_frame *f80211;

	uint16_t radiotap_len;
	char filter_pkg;

	int fc_len;
	int frame_body;
	
	
	
	struct access_point *ap_found;
	
	//TODO DOAR PENTRU TEST!
	const uint8_t invalid_bssid0[6]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
	
	
	
	
	//!de modificat valoarea minima a pachetelor!
	//!BUG 13 header->len or header->caplen?
	if (header->len<8){
		log_err(LEVEL5,(char *)"Invalid header len");
		return;
	}
		

/*
	time_struct=gmtime(&(header->ts.tv_sec));
	if (time_struct==NULL){
		log_err(LEVEL5,"Invalid timestamp");
		return;
	}
	
	if (strftime(arrival_time,sizeof(arrival_time),"%F %T",time_struct)==0){
		log_err(LEVEL5,"Invalid arrival_value (timestamp)");
		return ;
	}
*/		
//	printf("\nPacket number %d: len:%d\n timestamp:%s.%06ld",count,header->len,arrival_time,header->ts.tv_usec);
//	dbg_hex("pachet",packet,header->len);
	
	rd_init(&rd);
	
	//if (!is_offline){
	//	rd.seen=time(NULL);
	//}else{
		rd.seen=header->ts.tv_sec;
	//}
	
	if (radiotap_exist){
		radiotap_len=radiotap_get(&rd,packet,header->len);
		if (radiotap_len==0){
			log_err(LEVEL7,(char *)"Invalid radiotap header");
			return;
		}
	}else{
		radiotap_len=0;
	}
	
//	printf("Channel:%d Signal:%d Noise:%d\n",rd.channel,rd.signal,rd.noise);	

//	test[0]=0x08;
//	test[1]=0x20;

	
	f80211=(struct ieee80211_frame *)(packet+radiotap_len);
	
//	f80211=(struct ieee80211_frame *)(test);
	
	rd.protocol=f80211->frame_type&0x03;
	rd.type=(f80211->frame_type&0x0C)>>2;
	rd.subtype=(f80211->frame_type&0xF0)>>4;
	rd.type_subtype=(rd.type<<4)|rd.subtype;
	rd.flag_ds=f80211->flags&0x03;
	rd.is_protected=f80211->flags&0x40>>6;


	if (rd.is_protected==1){
		rd.cipher= rd.cipher | CIPHER_ENC;
		
	}
	

	
//	xxxxx
	

// 	
	//0100 0011
	
//	printf("protocol=%02x type=%02x subtype=%02x type_subtype=%02x frame_control=%02x  sizeof(frame_control)=%d radiotaplen:%d flag_ds=%d\n",rd.protocol,rd.type,rd.subtype,rd.type_subtype,f80211->frame_type,sizeof(f80211->frame_type),radiotap_len,rd.flag_ds);

	if (rd.protocol>0){
		log_err(LEVEL7,(char *)"Unsuported protocol!");
		return;
	}
	if (rd.type>2){
		log_err(LEVEL7,(char *)"Unsuported type");
		return;
	}

	
	fc_len=-1;
	frame_body=-1;

	//parse header for specific type of frame
	switch (rd.type){
		case IEEE80211_FRAME_CONTROL:
			fc_len=do_frame_control(&rd,f80211,&frame_body);
			rd.no=rd.no | NO_CONTROL;
			break;
		case IEEE80211_FRAME_DATA:
			fc_len=do_frame_data(&rd,f80211,(packet+radiotap_len),header->len-radiotap_len);
			rd.no=rd.no | NO_DATA;
			break;
		case IEEE80211_FRAME_MANAGEMENT:  
			fc_len=do_frame_management(&rd,f80211,(packet+radiotap_len),header->len-radiotap_len);
			rd.no=rd.no | NO_MANAGEMENT;
			break;
		default:
			log_err(LEVEL4,(char *)"Invalid frame type");
			return;
	}
	
	
//	printf("Fb:%d fc_len:%d\n",frame_body,fc_len);
	//printf("rd.type:%d\n",rd.type);
	
//	dbg_mac("DA",rd.da);
//	dbg_mac("SA",rd.sa);
//	dbg_mac("BSSID",rd.bssid);
	
	
	/*NU E ASA DAR PENTRU TEST...*/


//	printf("\33[%d;1H",no_ap);
//	no_ap++;

	filter_pkg=0;

	if (G.filter!=0){
		if ((G.filter&FILTER_BSSID)!=0){
			if (mac_equal(rd.bssid,G.filter_bssid)!=1){
				filter_pkg=1;
			}
		}
		//BUG 8 we never check addr4!
		if ((G.filter&FILTER_ADDRESS)!=0){
			if (mac_equal(rd.bssid,G.filter_address)!=1 && mac_equal(rd.da,G.filter_address)!=1 && mac_equal(rd.sa,G.filter_address)!=1){
				filter_pkg=1;
			}
		}
	}
	
	
	ap_found=NULL;
	
	//We should update all packets that are not filtered
	if (filter_pkg==0){
		
		
		//printf("\nPacket number %d: len:%d\n timestamp:%s.%06ld",count,header->len,arrival_time,header->ts.tv_usec);
		//	printf("flag:%02x type:%02x subtype:%02x protected=%d\n",f80211->flags,rd.type,rd.subtype,rd.protected);
		
		if (bssid_equal(rd.bssid,invalid_bssid0)==0){
			if (G.fap==NULL){
				G.fap=ap_add(NULL,rd);
				G.lap=G.fap;
				ap_found=G.lap;
			}else{
				if ((ap_found=ap_find(G.lap,rd.bssid))==NULL){
					G.lap=ap_add(G.lap,rd);
					ap_found=G.lap;
				}else{
					ap_update(ap_found,rd);
				}
			}
			if (G.offline==0)
				print_ap(G.fap);

			
#if QT_INTERFACE==1
			if (G.offline==0)
				if (ap_found!=NULL){
					qt_update_fields(ap_found);
			}
#endif
			
		
		}
	}
			
	rd_destroy(&rd);

	//if (frame_body==-1 || fc_len==-1){
	//	log_err(LEVEL5,"frame body or fclen invalid exiting");
	//}



//	arrival_time[19]='\0';
	

//	printf("\nPacket number %d: len:%d\n timestamp:%s - %d",count,header->len,arrival_time,sizeof(arrival_time));
	//printf("\nPacket number %d: len:%d\n timestamp:'%d'-%d-%d %d:%d:%d",count,header->len,arrival_time->tm_year,arrival_time->tm_mon,arrival_time->tm_mday,arrival_time->tm_hour,arrival_time->tm_min,arrival_time->tm_sec);
//	count++;

//	dbga("pachet",packet,header->len);

}




void got_pkg(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	
//	static unsigned  int i=0;	
//	i++;
//	printf("i:%d\n",i);
	//if packet has a radiotap header

//Save the last pkg
#if DEBUG_MODE==1
	G.dbg_header=header;
	G.dbg_packet=packet;
#endif
	
	if (G.datalink==DLT_IEEE802_11_RADIO){
		do_pkg(header,packet,1,G.offline);
	}else{
		do_pkg(header,packet,0,G.offline);
	}
	
	//!TODO Implement filter in dump!
	//!BUG 14 Implement filter in dump!
	
	if (G.dump==1){
		//G.offline
		pcap_dump((u_char *)G.write_fd, header, packet);
	}

#if QT_INTERFACE==1	
	if (G.offline==1){
		qt_update_progress_bar(header->caplen);
	}
#endif	
//	if (time(NULL)-G.start_time>30){
//		log_err(LEVEL0,"Iesim");
//	}
	
}


//init for global variables
void G_init(void)
{
	G.lap=NULL;
	G.fap=NULL;
	G.read_file=NULL;
	G.write_file=NULL;
	G.offline=0;
	G.dump=0;
	G.datalink=0;
	
	G.dev_name=NULL;
	
	G.dev_fd=NULL;
	G.write_fd=NULL;
	
	G.start_time=0;
	
	
	//user interface
	G.ui=0;
	
	
//	G.channel=NULL;
	G.freq=NULL;
	G.child=0;
	
	G.filter=0;
	mac_init(G.filter_bssid);
	mac_init(G.filter_address);
	
	
	
	
#if DEBUG_MODE==1
	G.dbg_header=NULL;
	G.dbg_packet=NULL;
	//G.is_child=0;
#endif
	
}


void G_destroy(void)
{
	//to free all memory 
}


#if DEBUG_MODE==1
void debug()
{

	pcap_dumper_t *dbg_fd;
	time_t dbg_ct;
	struct tm *dbg_time_struct;
	char dbg_exit_time[20];
	char *dbg_fname;
	
//maybe we should write structure?!
	if (G.dev_fd==NULL){
		return;
	}
	
	if (G.child!=0){
		return;
	}

	dbg_fname=NULL;
	dbg_ct=time(NULL);
	dbg_time_struct=gmtime(&dbg_ct);
	if (dbg_time_struct==NULL){
		//log_err(LEVEL5,"Can't generate time for naming debug files: Invalid timestamp");
		printf("\nCan't generate time for naming debug files: Invalid timestamp\n");
		//return;
	}else{
		if (strftime(dbg_exit_time,sizeof(dbg_exit_time),"%Y%m%d%H%M",dbg_time_struct)==0){
			//log_err(LEVEL5,"Invalid arrival_value (timestamp)");
			printf("\nCan't generate time for naming debug files: Invalid exit_time\n");
			//return ;
		}else{
			dbg_fname=str_mk((char *)"%s/%s-%s.dbg.cap",(char *)DEBUG_FOLDER,(char *)APP_NAME,(char *)dbg_exit_time);
		}
	}
	
//BUG 4 to verify if the file exist
	if (dbg_fname==NULL){
		srand(time(NULL));
		dbg_fname=str_mk((char *)"%s/%s-%d.dbg.cap",(char *)DEBUG_FOLDER,(char *)APP_NAME,rand());
	}
	
	
	dbg_fd=pcap_dump_open(G.dev_fd, dbg_fname);
	if (dbg_fd!=NULL){
		if (G.dbg_header!=NULL && G.dbg_packet!=NULL){
			pcap_dump((u_char *)dbg_fd,G.dbg_header,G.dbg_packet);
			pcap_dump_flush(dbg_fd);
			pcap_dump_close(dbg_fd);
		}else{
			printf("\nCan't write debug file because i have got no packets\n");
			return;
		}
	}else{
		printf("\nCan't write debug file: '%s' reason: %s\n",dbg_fname,pcap_geterr(G.dev_fd));
		return;
	}

	printf("\n\nDebug informations wrote on: '%s'\n\n",dbg_fname);
	

}
#endif

void stop_clean(void)
{

	if (G.write_fd!=NULL){
		pcap_dump_flush(G.write_fd);
	}	
	
#if DEBUG_MODE==1
	if (G.dbg_header!=NULL){
		G.dbg_header=NULL;
	}
	
	if (G.dbg_packet!=NULL){
		G.dbg_packet=NULL;
	}
#endif	
	
}


void new_dev_clean(void)
{
	if (G.dev_fd!=NULL){
		pcap_close(G.dev_fd);
		G.dev_fd=NULL;
	}
	
	if (G.dev_name!=NULL){
		free(G.dev_name);
		G.dev_name=NULL;
	}

	if (G.write_fd!=NULL){
		pcap_dump_flush(G.write_fd);
		pcap_dump_close(G.write_fd);
		G.write_fd=NULL;
		G.dump=0;
	}	

#if DEBUG_MODE==1	
	if (G.dbg_header!=NULL){
		G.dbg_header=NULL;
	}
	
	if (G.dbg_packet!=NULL){
		G.dbg_packet=NULL;
	}
#endif
	
	if (G.read_file!=NULL){
		free(G.read_file);
		G.read_file=NULL;
	}
	//?!
	if (G.write_file==NULL){
		free(G.write_file);
		G.write_file=NULL;
	}	
	
	G.offline=0;
	G.dump=0;
	G.datalink=0;
	
}


void ap_clean(void)
{

	struct access_point *tmp;
	
	if (G.write_fd!=NULL){
		pcap_dump_flush(G.write_fd);
		pcap_dump_close(G.write_fd);
		G.write_fd=NULL;
	}

	
	if (G.dev_fd!=NULL){
		pcap_close(G.dev_fd);
		G.dev_fd=NULL;
	}
	
	
	if (G.read_file!=NULL){
		free(G.read_file);
		G.read_file=NULL;
	}
	
	if (G.write_file==NULL){
		free(G.write_file);
		G.write_file=NULL;
	}
	

#if DEBUG_MODE==1	
	if (G.dbg_header!=NULL){
		G.dbg_header=NULL;
	}
	
	if (G.dbg_packet!=NULL){
		G.dbg_packet=NULL;
	}
#endif
	
	G.lap=NULL;
	tmp=G.fap;
	
	while (tmp!=NULL){
		G.fap=tmp->next;
		free(tmp);
		tmp=G.fap;
	}

}



void main_clean(void)
{
	struct access_point *tmp;
	
	if (G.dev_fd!=NULL){
		pcap_close(G.dev_fd);
		G.dev_fd=NULL;
	}
	
	if (G.dev_name!=NULL){
		free(G.dev_name);
		G.dev_name=NULL;
	}

	if (G.write_fd!=NULL){
		pcap_dump_flush(G.write_fd);
		pcap_dump_close(G.write_fd);
		G.write_fd=NULL;
		G.dump=0;
	}	

#if DEBUG_MODE==1	
	if (G.dbg_header!=NULL){
		G.dbg_header=NULL;
	}
	
	if (G.dbg_packet!=NULL){
		G.dbg_packet=NULL;
	}
#endif
	
	if (G.read_file!=NULL){
		free(G.read_file);
		G.read_file=NULL;
	}
	
	if (G.write_file==NULL){
		free(G.write_file);
		G.write_file=NULL;
	}

	if (G.freq!=NULL){
		free(G.freq);
		G.freq=NULL;
	}
	
	G.lap=NULL;
	tmp=G.fap;
	
	while (tmp!=NULL){
		G.fap=tmp->next;
		free(tmp);
		tmp=G.fap;
	}
	
	
	
}



/*sets the channel indicated by uint8_t channel
GLOBAL_VAR USED:
		pcap_t *G.dev_fd
		char *G.dev_name
INPUT:
		uint8_t channel
OUTPUT:
		on success: 0
		on error:  -1
*/
//!TODO PORT on WINDOWS 
int set_channel(uint8_t channel)
{
	struct	iwreq chn;
	int dev_fd;
	char *dev_name;
	
	dev_fd=pcap_get_selectable_fd(G.dev_fd);
	dev_name=G.dev_name;
	
	strncpy(chn.ifr_ifrn.ifrn_name,dev_name,IFNAMSIZ);
	chn.u.freq.e=0;
	chn.u.freq.m=channel;
	chn.u.freq.flags=IW_FREQ_FIXED;
	if (ioctl(dev_fd,SIOCSIWFREQ,&chn)!=0){
		log_err(LEVEL5,(char *)"Error setting the channel:%s\n",strerror(errno));
		return -1;
	}else{
		return 0;
	}
}



//!TODO PORT on WINDOWS 
int set_freq(uint16_t freq)
{
	struct	iwreq frq;
	int dev_fd;
	char *dev_name;
	
	if (G.dev_name==NULL){
		log_err(LEVEL5,(char *)"No dev_name in set_freq");
		return -1;
	}
	

	if (G.dev_fd==NULL){
		log_err(LEVEL5,(char *)"No dev_fd in set_freq");
		return -1;
	}
	
	
	dev_fd=pcap_get_selectable_fd(G.dev_fd);
	dev_name=G.dev_name;
	
	strncpy(frq.ifr_ifrn.ifrn_name,dev_name,IFNAMSIZ);
	frq.u.freq.e=6;
	frq.u.freq.m=freq;
	frq.u.freq.flags=IW_FREQ_FIXED;
	if (ioctl(dev_fd,SIOCSIWFREQ,&frq)!=0){
		log_err(LEVEL5,(char *)"Error setting the channel:%s\n",strerror(errno));
		return -1;
	}else{
		return 0;
	}
}

//int valid_channel(char channel)
//{
//	while (


//counts the number of commas in a string (used in parsing freq and channels) 
//verifies if all characters are comas or numbers
int no_ofcommas(char *str)
{
	int no;
	int i;
	
	no=1;
	i=0;
	
	while (str[i]!='\0'){
		if (str[i]==','){
			no++;
		}else{
			if (isdigit(str[i])==0){
				log_err(LEVEL2,(char *)"Invalid number character %c",str[i]);
				return -1;
			}
		}
		i++;
	}
	
	return no;
}


//determine if uint16_t freq is a supported freqency for the wireless card
char is_freq(uint16_t freq)
{
	
	uint16_t *x;
	int i;
	
	i=0;
	
	x=get_supported_freq();
	if (x!=NULL){
		while (x[i]!=0){
			if (x[i]==freq){
				free(x);
				return 1;
			}
			i++;
		}
		free(x);
		return 0;
	}else{
		return -1;
	}
}

char is_channel(uint8_t channel)
{
	uint16_t freq;
	freq=ieee80211chan2mhz((uint8_t)channel);
	return is_freq(freq);
}



int verify_freq()
{
	
	int i;
	i=0;
	
	if (G.freq==NULL){
		return -1;
	}
	
	while (G.freq[i]!=0){
		//printf("ch: %d\n",G.freq[i]);
		if (is_freq(G.freq[i])!=1){
			log_err(LEVEL10,(char *)"Unsuported channel %d (%d)",ieee80211mhz2chan(G.freq[i]),G.freq[i]);
			return i+1;
		}
			
		i++;
	}
	
	return 0;

}




//PARSING FUNCTION!!!
int parse_own_channels(char *channels)
{
	int str2int;
	int no_channels;
	int i;
	char *x;
	
	if (channels==NULL){
		log_err(LEVEL0,(char *)"Invalid channel argument");
		return -1;
	}
	
	no_channels=no_ofcommas(channels);

	if (no_channels<=0){
		log_err(LEVEL1,(char *)"Can't parse channels");
		return -1;
	}
	
	if (G.freq!=NULL){
		free(G.freq);
		G.freq=NULL;
	}

	G.freq=(uint16_t *)xmalloc(sizeof(uint16_t)*(no_channels+1));
	x=strtok(channels,",");
	for (i=0;i<no_channels;i++){
		if (x!=NULL){
			str2int=atoi(x);
			if (str2int>255){
				log_err(LEVEL1,(char *)"Invalid channel >255");
				free(G.freq);
				G.freq=NULL;
				return -1;
			}
			if (str2int<=0){
				log_err(LEVEL1,(char *)"Invalid channel argument <0");
				free(G.freq);
				G.freq=NULL;
				return -1;
			}
			
			G.freq[i]=ieee80211chan2mhz((uint8_t)str2int);
		}else{
			log_err(LEVEL1,(char *)"Invalid channel argument. Number of channels differs from reality");
			free(G.freq);
			G.freq=NULL;
			return -1;
		}
		x=strtok(NULL,",");
	}
	G.freq[no_channels]=0;
	
	return no_channels;
}

uint16_t *current_freq(void)
{
	return G.freq;
}


//channels MUST finish in 0
int init_default_channels(uint8_t *channels)
{
	uint16_t *tmp_freq;
	unsigned int len;
	unsigned int i,Gi;
	
	len=0;
	while (channels[len++]!=0){
		if (len>=MAX_NO_CHANNELS){
			log_err(LEVEL1,(char *)"Can't init default channles (can't find ending of the channels)");
			return -1;
		}
	}
	
	
	if (len<=1){
		log_err(LEVEL1,(char *)"Invalid len of default channels");
		return -1;
	}
	
	
	tmp_freq=(uint16_t *)xmalloc(sizeof(uint16_t)*(len+1));
	
	Gi=0;
	for (i=0;i<len;i++){
		if (is_channel(channels[i])==1){
			tmp_freq[Gi++]=(uint16_t)ieee80211chan2mhz(channels[i]);
			
		}
	}
	
	if (Gi==0){
		log_err(LEVEL1,(char *)"Can't find any supported channel from default list");
		free(tmp_freq);
		return -1;
	}
	
	
	G.freq=(uint16_t *)xmalloc(sizeof(uint16_t)*(Gi+1));
	memcpy(G.freq,tmp_freq,Gi*sizeof(uint16_t));
	
	
	free(tmp_freq);
	
	return Gi;
}


int get_channel(int index)
{
	return ieee80211mhz2chan(G.freq[index]);
}

int get_freq(int index)
{
	return G.freq[index];
}


const struct access_point *get_fap(void)
{
	return G.fap;
}

const struct access_point *get_iap(uint16_t index)
{
	const struct access_point *z;
			
	z = G.fap;
	
	while (z != NULL){
		if (z->id == index){
			return z;
		}
		z = z->next;
	}
	
	
	return NULL;
}


//To use only in fork 
//
void freq_hop(useconds_t delay)
{
	int i;
	
	
	if (G.child==0){
		log_err(LEVEL0,(char *)"Function channels_hop must be called in child");
		return;
	}
	
	i=0;
	while (1){
		
		if (G.freq[i]!=0){
			//`fprintf(stderr,"setez:%u",G.freq[i]);
			if (set_freq(G.freq[i])!=0){
				log_err(LEVEL1,(char *)"Can't set the channel!");
				return;
			}
			//printf("CHN:%d\n",ieee80211mhz2chan(G.freq[i]));
			usleep(delay*1000);
			i++;
		}else{
			i=0;
			//log_err(LEVEL1,"test");
			//just for test 
			//exit(1);
		}
	}

}

//To use only in thread
//
void freq_hop_thread(useconds_t delay)
{
	int i;
	
	
	i=0;
	while (1){
		
		if (G.freq[i]!=0){
			//`fprintf(stderr,"setez:%u",G.freq[i]);
			if (set_freq(G.freq[i])!=0){
				log_err(LEVEL1,(char *)"Can't set the channel!");
				return;
			}
			//printf("CHN:%d\n",ieee80211mhz2chan(G.freq[i]));
			usleep(delay*1000);
			i++;
		}else{
			i=0;
			//log_err(LEVEL1,"test");
			//just for test 
			//exit(1);
		}
	}

}




void *main_hop(void *argv)
{
	//useconds_t hop_delay;
	//hop_delay=DEFAULT_HOP_DELAY;
	freq_hop_thread(DEFAULT_HOP_DELAY);
	return NULL;
}


char do_range(struct iw_range *range)
{
	struct iwreq wrq;
	char *dev_name;
        //struct iw_range range;

	int dev_fd;

	
	
	if (G.dev_fd==NULL || G.dev_name==NULL){
		log_err(LEVEL0,(char *)"Found uninitialized device when searching supported channels");
		return 0;
	}
	
	
	memset(range, 0, sizeof(struct iw_range));
	

	dev_fd=pcap_get_selectable_fd(G.dev_fd);
	dev_name=G.dev_name;
	
	strncpy(wrq.ifr_name,dev_name,IFNAMSIZ);

	wrq.u.data.pointer = range;
	wrq.u.data.length = sizeof(struct iw_range);
	wrq.u.data.flags = 0;

	if (ioctl(dev_fd, SIOCGIWRANGE, &wrq ) != 0 ){
		log_err(LEVEL5,(char *)"Error getting the channels:%s\n",strerror(errno));
		return 0;
	}
	
	
	if (range->num_frequency==0){
		log_err(LEVEL1,(char *)"Can't find any supported channels");
		return 0;
	}
	
	//return range;
	return 1;
}


uint16_t *get_supported_freq(void)
{
	struct iw_range range;
	int i;
	uint16_t *supp_freq;
	uint32_t tmp_freq;
	
	if (do_range(&range)==0){
		log_err(LEVEL7,(char *)"No range");
		return NULL;
	}
	
	supp_freq=(uint16_t *)xmalloc(sizeof(uint16_t)*(range.num_frequency+1));
	
	for (i = 0; i < range.num_frequency; ++i){
		
		tmp_freq=range.freq[i].m*powl(10,(range.freq[i].e))/1000000.0;
		
		if ((tmp_freq>>16)>=1 || tmp_freq==0){
			log_err(LEVEL5,(char *)"Got invalid freqency");
			free(supp_freq);
			return NULL;
		}
		supp_freq[i]=tmp_freq;
	}
	
	supp_freq[range.num_frequency]=0;
	
	return supp_freq;
}


uint8_t *get_supported_channels(void)
{
	struct iw_range range;
	int i;
	uint8_t *supp_chann; //supproted channels
	
	uint32_t tmp_freq;
	    
	if (do_range(&range)==0){
		log_err(LEVEL7,(char *)"No range");
		return NULL;
	}
	
	supp_chann=(uint8_t *)xmalloc(sizeof(uint8_t)*(range.num_frequency+1));
	
	for (i = 0; i < range.num_frequency; ++i){
		

		tmp_freq=range.freq[i].m*powl(10,(range.freq[i].e))/1000000.0;
		
		if ((tmp_freq>>16)>=1 || tmp_freq==0){
			log_err(LEVEL5,(char *)"Got invalid freqency");
			free(supp_chann);
			return NULL;
		}
//FIXME: see at begining of this document
//marked as BUG 5 (Japan BUG) 
		if (tmp_freq>=JAPAN_FREQ_UNSUPORTED_MIN && tmp_freq<=JAPAN_FREQ_UNSUPORTED_MAX){
			supp_chann[i]=-1;
		}else{
			supp_chann[i]=ieee80211mhz2chan(tmp_freq);
		
		}
	}
	supp_chann[range.num_frequency]=0;
	
	return supp_chann;
}


	




void wpa_receive_passphrase(uint8_t key[128],char *str)
{
	unsigned int i;
	for (i=0;i<strlen(str);i++){
		key[i]=str[i];
	}

}
	
	
//!todo verify all data
int mic_calc(uint8_t mic[20],const char *essid,const uint8_t bssid[],const uint8_t stmac[],const uint8_t snonce[],const uint8_t anonce[],const uint8_t eapol[],int eapol_size,int eapol_ver, char *pass)
{
	
	//char *data=(char *)"123456789";
	
	/*char *essid="AP";
	uchar eapol[]={
	0x01 ,0x03 ,0x00 ,0x77 ,0x02 ,0x01 ,0x09 ,0x00 ,
	0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x01 ,0xe6 ,0x93 ,0x97 ,0xd5 ,0x0a ,0x3c ,0x94 ,
	0x52 ,0x23 ,0x22 ,0xb2 ,0x4d ,0x9d ,0x1f ,0x1b ,0xeb ,0x34 ,0x6c ,0x78 ,0xae ,0x56 ,0xc9 ,0x0f ,
	0x30 ,0x92 ,0x92 ,0x98 ,0x80 ,0x03 ,0x2e ,0x1b ,0x8e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x30, 0x16, 0x01, 0x00, 0x00,
	0x0f, 0xac, 0x02, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x3c, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	*/
	//, 0x00, 0xe6 ,0x93 ,0x97 ,0xd5 ,0x0a ,0x3c ,0x94 ,0x52 ,0x23 ,0x22 ,0xb2 ,0x4d ,0x9d ,0x1f ,0x1b ,0xeb ,0x34 ,0x6c ,0x78 ,0xae ,0x56 ,0xc9 ,0x0f ,0x30 ,0x92 ,0x92 ,0x98 ,0x80 ,0x03 ,0x2e};
	uint8_t key[128];
	uint8_t pmk[128];
	//uint8_t mic[20];
	uint8_t ptk[80];
	uint8_t pke[100];
	int i;
	//unsigned int eapol_size;
	
	/*
	uchar bssid[6]={00,0x16,0x0a,0x18,0x92,0x42};
	uchar stmac[6]={0x00,0x18,0xde,0xbb,0x2a,0x50};
	
	uchar snonce[]={0x13 ,0x2d ,0xbe ,0xe4 ,0x11 ,0x22 ,0x52 ,0x0e ,0x13 ,0x30 ,0xdc ,0x03 ,0x3d ,0xf4 ,0x8a ,0x45,
			0x68 ,0x29 ,0xc0 ,0x9e ,0x60 ,0x61 ,0x51 ,0x7c ,0x23 ,0x87 ,0x1b ,0x1c ,0x5c ,0x3b ,0xd4 ,0x43};

	uchar anonce[]={0xe6 ,0x93 ,0x97 ,0xd5 ,0x0a ,0x3c ,0x94 ,0x52 ,0x23 ,0x22 ,0xb2 ,0x4d ,0x9d ,0x1f ,0x1b ,0xeb,
			0x34 ,0x6c ,0x78 ,0xae ,0x56 ,0xc9 ,0x0f ,0x30 ,0x92 ,0x92 ,0x98 ,0x80 ,0x03 ,0x2e ,0x1b ,0x8e};
*/

	assert(pass);
	//if (pass==NULL){
		//log_err(LEVEL1,"Null password");
		//return -1;
	//}	
	
	memset(key,0,128);
	memset(pmk,0,128);
	memset(mic,0,20);
	memset(ptk,0,80);
	memset(pke,0,100);


	wpa_receive_passphrase(key, pass);
	//pr((char *)"key",key,128);

	calc_pmk( (char *)key, (char *)essid, pmk);

	//pr((char *)"PMK",pmk,128);


	/* pre-compute the key expansion buffer */
	memcpy( pke, "Pairwise key expansion", 23 );
	if( memcmp( stmac, bssid, 6 ) < 0 ){
		memcpy( pke + 23, stmac, 6 );
		memcpy( pke + 29, bssid, 6 );
	} else {
		memcpy( pke + 23, bssid, 6 );
		memcpy( pke + 29, stmac, 6 );
	}
	
	if( memcmp( snonce, anonce, 32 ) < 0 ) {
		memcpy( pke + 35, snonce, 32 );
		memcpy( pke + 67, anonce, 32 );
	} else {
		memcpy( pke + 35, anonce, 32 );
		memcpy( pke + 67, snonce, 32 );
	}

	
			

	//pr((char*)"PKE",pke,100);

	
	for (i = 0; i < 4; i++)
	{
		pke[99] = i;
		HMAC(EVP_sha1(), pmk, 32, pke, 100, ptk + i * 20, NULL);
		//HMAC(EVP_sha1(), pmk[j], 32, e, 100, ptk[j] + i * 20, NULL);
	}
	

	//pr((char *)"PTK",ptk,80);

	
	//eapol_size=strlen(eapol);

	
	//printf("EAPOL_SIZE:%d\n",eapol_size);
	//pr((char *)"EAPOL",eapol,eapol_size);
	
	if (eapol_ver==1)
		HMAC(EVP_md5(), ptk, 16, eapol, eapol_size, mic, NULL);
	else
		HMAC(EVP_sha1(), ptk, 16, eapol, eapol_size, mic, NULL);
	
	//pr((char *)"MIC",mic,20);
	
	return 0;

}


//PLEASE verify if ap and pass are not null
int pass_find(const struct access_point *ap,char *pass)
{
	

	int cret;
	uint8_t mic[20];
	
	

	cret=-1;
	assert(ap);
	assert(pass);
	//if (ap!=NULL){

		if (ap->wpa_new!=NULL){
			if (((ap->wpa_new->state & EAPOL_STATE2) != 0) && ((ap->wpa_new->state & EAPOL_STATE1) != 0)){
				cret=mic_calc(mic,ap->ssid,ap->bssid,ap->wpa_new->stmac,ap->wpa_new->snonce,ap->wpa_new->anonce,ap->wpa_new->eapol,ap->wpa_new->eapol_size,ap->wpa_new->version,pass);
			}else{
				log_err(LEVEL10,"We need first two messages from handshake");
				return -1;
			}
			if (cret==0){
				if (memcmp(mic,ap->wpa_new->mic,AUTH_MIC_SIZE)==0){
					return 1;
				}else{
					return 0;
				}
			}else{
				return -1;
			}
			
		}
		
		if (ap->wpa!=NULL){
			
			if (((ap->wpa->state & EAPOL_STATE2) != 0) && ((ap->wpa->state & EAPOL_STATE1) != 0)){
				cret=mic_calc(mic,ap->ssid,ap->bssid,ap->wpa->stmac,ap->wpa->snonce,ap->wpa->anonce,ap->wpa->eapol,ap->wpa->eapol_size,ap->wpa->version,pass);
			}else{
				log_err(LEVEL10,"We need first two messages from handshake");
				return -1;
			}
			if (cret==0){
				if (memcmp(mic,ap->wpa->mic,AUTH_MIC_SIZE)==0){
					return 1;
				}else{
					return 0;
				}
			}else{
				return -1;
			}
		
		}
		
		return -1;
		
		
	//}else{
		//log_err(LEVEL1,"NULL AP in pass find");
		//return -1;
	//}
}

/*
  reads a line from the file descriptor fd
  max size of line is PASSCODE_MAX
  min size of the line is PASSCODE_MIN
  
  INPUT:
	fd - file descriptor
  OUTPUT:	
	line[PASSCODE] - line read
	line_size - number of characters read

  RETURN:
	-1 on error
	0 on end of file
	1 on success 

	
		
*/
char pass_line_read(int fd,char line[PASSCODE_MAX],int *line_size)
{
	
	ssize_t readret;
	char find_new_line;
	char ch;
	
	*line_size=0;
	
	//readret=1;
	find_new_line=0;
	
	while (1){
		
		if (find_new_line==0){
			while (*line_size<PASSCODE_MAX){
				
				if ((readret=read(fd,&ch,sizeof(uint8_t)))<0){
					log_err(LEVEL1,"Can't read dictionary  : %s",strerror(errno));
					return -1;
				}
				
				if (readret==0){
					line[*line_size] = '\0';
					//*line_size = *line_size+1;
					return 0;
				}
				
				if (ch == '\n'){
					if (*line_size>=PASSCODE_MIN){
						line[*line_size]='\0';
						//*line_size = *line_size+1;
						return 1;
					}else{
						*line_size=0;
					}
				}else{
					line[*line_size]=ch;
					*line_size = *line_size+1;
				}
				
				
			}
			//line[*line_size-1]='\0';
			find_new_line=1;
		}else{
			
			while (find_new_line==1){
				if ((readret=read(fd,&ch,sizeof(uint8_t)))<0){
					log_err(LEVEL1,"Can't read dictionary: %s",strerror(errno));
					return -1;
				}
				
				if (readret==0){
					line[0]='\0';
					*line_size=0;
					return 0;
				}
				
				if (ch == '\n'){
					find_new_line=0;
					*line_size=0;
				}
			}	
		}	
	}
	
	
}

inline unsigned char is_part_handshake(const struct access_point *ap)
{
	//if (ap==NULL){
	//	log_err(LEVEL1,"Can't find handshake for a null ap");
	//	return 0;
	//}
	
	assert(ap);
	
	if (ap->wpa_new!=NULL){
		if (((ap->wpa_new->state & EAPOL_STATE2) != 0) && ((ap->wpa_new->state & EAPOL_STATE1) != 0)){
			return 1;
		}
	}
	
	if (ap->wpa!=NULL){
		
		if (((ap->wpa->state & EAPOL_STATE2) != 0) && ((ap->wpa->state & EAPOL_STATE1) != 0)){
			return 1;
		}
	}
	
	return 0;
	
}


//pass MUST HAVE at least PASSCODE_MAX
int try_dict(const char *fname,const struct access_point *ap,char pass[PASSCODE_MAX])
{
	char line[PASSCODE_MAX];
	int fd;
	char read_ret;
	int line_size;
	
	//fprintf(stdout, "\033[2J");
	//fprintf(stdout, "\033[1;1H");
	
	fd = open(fname,0);
	
	if (fd<0){
		log_err(LEVEL1,"Can't open dictionary: %s",strerror(errno));
		return ERR_DICT_CANT_OPEN;
	}
	
	if (ap == NULL){
		log_err(LEVEL1,"Null access point in try_dict");
		return ERR_DICT_AP_NULL;
	}
	
	
	if (pass == NULL){
		log_err(LEVEL1,"Null pass in try_dict");
		return ERR_DICT_PASS_NULL;
	}
	
	if (is_part_handshake(ap)!=1){
		log_err(LEVEL1,"Can't find first two auth pkgs for this ap");
		return ERR_DICT_NO_EAPOL;
	}
	
	memset(line,0,PASSCODE_MAX);
	
	read_ret = pass_line_read(fd,line,&line_size);
	
	while (read_ret > 0){
		
		if (read_ret<0){
			log_err(LEVEL1,"Can't read from dict");
			close(fd);
			return ERR_DICT_CANT_READ_LINE;
		}

		//printf("text: '%s' - %d\n",line,line_size);
		
		if (pass_find(ap,line)==1){
			//printf("FOUND: '%s' - %d\n",line,line_size);
			memcpy(pass,line,line_size*sizeof(char));
			pass[line_size]='\0';
			close(fd);
			return line_size;
		}
		
		read_ret = pass_line_read(fd,line,&line_size);
		
	}
	
	if (read_ret == 0){
		//!!!!!!!!!!!!
		if (line_size>0){
			if (pass_find(ap,line)){
				memcpy(pass,line,line_size*sizeof(char));
				pass[line_size]='\0';
				close(fd);
				return line_size;
				//printf("FOUND: '%s' - %d\n",line,line_size);
			}else{
				close(fd);
				return 0;
			}
		}
	}
	
	if (read_ret < 0){
		log_err(LEVEL2,"Error reading line");
		return ERR_DICT_CANT_READ_LINE;
	}
	
	close(fd);
	return 0;
	
	
}



void *crack_thread(void *argv)
{
	struct th_crack *crack_args;
	char pass[PASSCODE_MAX];
	char *err;
	char *x;
	int try_ret;
	
	crack_args = (struct th_crack *)argv;
	
	log_err(LEVEL10,"ap->id= %u ",crack_args->ap->id);
	log_err(LEVEL10,"ap->ss= %s ",crack_args->ap->ssid);
	log_err(LEVEL10,"args= %s ",crack_args->fname);
	//x_message("DAAA mergeeeeeee");
	//log_err(LEVEL1,"args2= %s ",crack_args->fname2);
	//while (1){
	//;
	//}
	
	memset(pass,'\0',PASSCODE_MAX);
	try_ret = try_dict(crack_args->fname,crack_args->ap,pass);
	
	
	
	if (try_ret<0){
		err=(char *)xmalloc(sizeof(char)*(ERROR_MAX));
		memset(err,'\0',ERROR_MAX);
		switch (try_ret){
			case ERR_DICT_CANT_OPEN:
				strncpy(err,"Can't open dictionary",ERROR_MAX-1);
				break;
			case ERR_DICT_AP_NULL:
				strncpy(err,"Null ap in cracking",ERROR_MAX-1);
				break;
			case ERR_DICT_PASS_NULL:
				strncpy(err,"Password is null?!",ERROR_MAX-1);
				break;
			case ERR_DICT_NO_EAPOL:
				strncpy(err,"This AP has no eapol message",ERROR_MAX-1);
				break;
			case ERR_DICT_CANT_READ:
				strncpy(err,"Can't read from dictionary",ERROR_MAX-1);
				break;
			case ERR_DICT_CANT_READ_LINE:
				strncpy(err,"Can't read a line from dictionary",ERROR_MAX-1);
				break;
			default:
				strncpy(err,"Unknown error in cracking",ERROR_MAX-1);
		}
		err[ERROR_MAX-1]='\0';
		log_err(LEVEL1,err);
		x_message(err);
		//free(err);
	}else{
		if (try_ret == 0){
			x=str_mk("Password not found");
			x_message(x);
		}else{
			x=str_mk("Password is: '%s'",pass);
			x_message(x);
			
		}
		
	}
	
	crack_finish(1);
	
	//free(crack_args);		  
	return NULL;
	
}

void tmp_crack(struct access_point *lap){
	
	struct access_point *ap;
	char pass[PASSCODE_MAX];
	
	ap=lap;
	fprintf(stdout, "\033[2J");
	fprintf(stdout, "\033[1;1H");
	 
	 while (ap!=NULL){
		 	 printf("Ap:\n");
		//nu e asa de verificat si starea
		if (ap->wpa!=NULL){
			if (try_dict("test.txt",ap,pass)!=0){
				printf("Found pass:'%s'\n",pass);
				return ;
			}
			//printf("Found: %d, pass:%s\n",pass_find(ap,pass),pass);
		}
		
		ap=ap->prev;
	}
	 printf("NOT Found:\n");
	 
}



char is_everything_set()
{
	if (G.offline==0){
		if (G.dev_name==NULL){
			return ERR_DEV_NAME_NOT_FOUND;
		}
	}else{
		if (G.read_file==NULL){
			return ERR_READ_FILE_NOT_FOUND;
		}	}	
	if (G.dev_fd==NULL){
		return ERR_DEV_DF_NOT_FOUND;
	}
	
	if (G.dump==1){
		if (G.write_file==NULL){
			return ERR_WRITE_FILE_NOT_FOUND;
		}
		if (G.write_fd==NULL){
			return ERR_WRITE_FD_NOT_FOUND;
		}
	}
	
	return 0;
	
}

void *main_loop(void *argv)
{

	int rloop;
#if QT_INTERFACE==1
	char *ret_msg;
	ret_msg=NULL;
#endif
	
	if (G.dev_fd==NULL){
		//JUST WARN!!!!
		log_err(LEVEL1,(char *)"Device not initialised");
		//pthread_exit(NULL);
//		thread_stop();
		#if QT_INTERFACE==1
			ret_msg=str_mk((char *)"Device not initialised");
			return ret_msg;
		#endif
	}else{
	
	while (1){

		rloop=pcap_loop(G.dev_fd, -1, got_pkg, NULL);
		
		if (rloop<0){
			if (G.dev_fd!=NULL){
				log_err(LEVEL1,(char *)"Loop failed: %s",pcap_geterr(G.dev_fd));

#if QT_INTERFACE==1
				ret_msg=str_mk((char *)"Loop failed: %s",pcap_geterr(G.dev_fd));
				qt_exit_unexpected(pcap_geterr(G.dev_fd),G.fap);
				return ret_msg;	
#endif
			}else{
				log_err(LEVEL1,(char *)"Loop failed");

#if QT_INTERFACE==1
				ret_msg=str_mk((char *)"Loop failed.");
				qt_exit_unexpected(NULL,G.fap);
				return ret_msg;	
#endif
			}
			return NULL;
		}
		//printf("rloop=%d",rloop);

		if (rloop==0 && G.offline==1){
//!TODO PRINT ON GUI?! 
			#if QT_INTERFACE==1
				qt_insert_all(G.fap);			
			#endif
			
			print_ap(G.fap);
			
			//tmp_crack(G.lap);
			//exit(1);
			return NULL;
		}		
	}
	}

}


/*set the current interface
INCOMPLETE!
  GLOBAL INPUT: G.offline
				G.dev_name
				G.read_file (if G.offline=1)
				
  GLOBAL OUTPUT: G.dev_fd - file descriptor for pcap device
				 G.datalink - type of pcap device
  RETURN:
     0 on success
	-1 on error
        
*/
char set_interface(void)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	
	if (G.dev_fd!=NULL){
		log_err(LEVEL6, (char *)"Warining file descriptor not null in set interface!!!");
		pcap_close(G.dev_fd);
		G.dev_fd=NULL;
	}
	
	if (G.offline==0){
		G.dev_fd=pcap_open_live(G.dev_name,BUFSIZ,1,1000,errbuf);
		if (G.dev_fd==NULL){
			log_err(LEVEL0,(char *)"Couldn't open interface %s: %s",G.dev_name,errbuf); 
			return -1;
		}
		
		G.datalink=pcap_datalink(G.dev_fd);
		
		//!BUG 2 (labeled as)
		//!TODO here it could be a bug
		// we should check also  LINKTYPE_IEEE802_11=105 (which i think that is IEEE802_11 without radiotap header)
		// need proper hardware
		if (G.datalink!=DLT_IEEE802_11_RADIO && G.datalink!=DLT_IEEE802_11){
			log_err(LEVEL0, (char *)"%s is not an suported wireless interface (%d)\n", G.dev_name,G.datalink);
			pcap_close(G.dev_fd);
			G.dev_fd=NULL;
			return -1;
		}
	
	}else{
		if (G.read_file==NULL){
			log_err(LEVEL0,(char *)"Unknown file to read");
			return -1;
		}
		
		G.dev_fd=pcap_open_offline(G.read_file,errbuf);
		if (G.dev_fd==NULL){
			log_err(LEVEL0,(char *)"Couldn't open file %s: %s",G.read_file,errbuf); 
			return -1;
		}
		G.datalink=pcap_datalink(G.dev_fd);
	}
	return 0;
}

int console_list(char list)
{
	
	//list chanels and frequencies 
	if ((list&LIST_CHANNELS)!=0 && (list&LIST_FREQUENCIES)!=0){
		if (G.offline==1){
			log_err(LEVEL0,(char *)"Can't list supported channels and frequencies when packets are read from a file!");
			return -1;
		}else{
			print_supported_chan_freq();
		}
	}else{
		//list channels
		if ((list&LIST_CHANNELS)!=0){
			if (G.offline==1){
				log_err(LEVEL0,(char *)"Can't list supported channels when packets are read from a file!");
				return EXIT_FAILURE;
			}else{
				print_supported_channels();
				//exit(EXIT_SUCCESS);
			}
		}
		
		//list frequencies
		if ((list&LIST_FREQUENCIES)!=0){
			if (G.offline==1){
				log_err(LEVEL0,(char *)"Can't list supported frequencies when packets are read from a file!");
				return EXIT_FAILURE;
			}else{
				print_supported_freq();
				//exit(EXIT_SUCCESS);
			}
		}
	}
	return 0;
}




//just for display
void str_add(char str[MAX_STR_TO_DISPLAY],char *toadd)
{
	int length;
	if (str[0]=='\0'){
		strncpy(str,toadd,(MAX_STR_TO_DISPLAY-1)*sizeof(char));
	}else{
		length=strlen(str);
		strcpy(str+(length)," | ");
		length=length + strlen(" | ");
		strncpy(str+(length),toadd,(MAX_STR_TO_DISPLAY-1-length)*sizeof(char));
		//strncpy(str,
	}
}

//just for display
void str_enc(char str[MAX_STR_TO_DISPLAY],uint16_t cipher)
{
	     
	str[0]='\0';
	
	if ((cipher&CIPHER_WEP40)!=0){
		str_add(str,(char *)"WEP40");
	}
	
	if ((cipher&CIPHER_WEP104)!=0){
		str_add(str,(char *)"WEP104");
	}
	if ((cipher&CIPHER_CCMP)!=0){
		str_add(str,(char *)"CCMP");
	}
	if ((cipher&CIPHER_TKIP)!=0){
		str_add(str,(char *)"TKIP");
	}
	if ((cipher&CIPHER_PROPRIETARY)!=0){
		str_add(str,(char *)"PROP");
	}
	if ((cipher&CIPHER_WEP)!=0){
		str_add(str,(char *)"WEP");
	}
	if ((cipher&CIPHER_OPN)!=0){
		str_add(str,(char *)"OPN");
	}
	if ((cipher&CIPHER_ENC)!=0){
		str_add(str,(char *)"ENC");
	}
	
	if (str[0]=='\0'){
		str_add(str,(char *)"????");
	}
}


void str_enc_auth(char str[MAX_STR_TO_DISPLAY],uint8_t auth)
{
	
	str[0]='\0';
	
	if ((auth&AUTH_RSNA)!=0){
		str_add(str,(char *)"RSNA");
	}
	
	if ((auth&AUTH_PSK)!=0){
		str_add(str,(char *)"PSK");
	}

	if ((auth&AUTH_PROPRIETARY)!=0){
		str_add(str,(char *)"PROP");
	}
	
	
}





int init_scan_freq(char own_scan,char *no_channels)
{
	int verify_result;
	//scan with own freq/chann or leave current channel
		if (own_scan!=0){
			
			if (G.offline!=0){
				log_err(LEVEL1,(char *)"Can't use custom scan when reading from a file");
				return -1;
			}
			
			
			if ((own_scan & LEAVE_CURRENT_CHANNEL)!=0){
				
				*no_channels=0;
				//leave current channel (do nothing)
				if ((own_scan & (~LEAVE_CURRENT_CHANNEL))!=0){
					log_err(LEVEL1,(char *)"Can't set custom frequencies or channels because you used -L");
					return -1;
				}
				
			}else{
				
				//user wannts to set own channel
				if ((own_scan & SET_OWN_CHANNEL)!=0){
					if (G.offline!=0){
						log_err(LEVEL1,(char *)"Can't set channel in offline mode (packets are read from file)");
						return -1;
					}
					
					if ((own_scan & SET_OWN_FREQUENCIES)!=0){
						log_err(LEVEL1,(char *)"Can't use in the same time -c and -f");
						return -1;
					}
					
					if ((verify_result=verify_freq())!=0){
						if (verify_result==-1){
							log_err(LEVEL1,(char *)"Uninitialized variable used in testing frequency");
							return -1;
						}else{
							log_err(LEVEL1,(char *)"Unsuported channel %u (%u)",ieee80211mhz2chan(G.freq[verify_result-1]),G.freq[verify_result-1]);
							return -1;
						}
					}
					
				}
				
				if ((own_scan & SET_OWN_FREQUENCIES)!=0){
						log_err(LEVEL1,(char *)"Not implemented");
						return -1;
				}
				//exit(1);
				//set frequency as user wishes
				if (G.offline==0){
					if (*no_channels<=0){
						*no_channels=init_default_channels(default_channels);
					}
					
				}
			}
		}else{
			if (G.offline==0){
				*no_channels=init_default_channels(default_channels);
			//	dbg("no:%d",no_channels);
			//	i=0;
			
			//	while (default_channels[i]!=0){
			//		dbg("ch:%d",ieee80211mhz2chan(G.freq[i]));
			//		i++;
			//	}
			}else{
				*no_channels=0;
			}
			//	exit(1);
		}
		return 0;
}

//void *testx(void *argv){
	//while(1);
	//fprintf(stderr,"BAU");

	
//}
void free_dev_name(void)
{
	if (G.dev_name == NULL){
		log_err(LEVEL2,(char *)"Can't free a NULL device interface");
		return ;
	}
	free(G.dev_name);
	G.dev_name = NULL;
}

void set_dev_name(char *name)
{
	
	if (name == NULL){
		log_err(LEVEL2,(char *)"Can't set to NULL a device interface");
		return ;
	}
	if (G.dev_name!=NULL){
		free_dev_name();
	}
	
	G.dev_name = (char *)xmalloc(sizeof(char)*(strlen(name) + 1));
	strcpy(G.dev_name,name);
}

uint8_t is_dev_set(void)
{
	if (G.dev_fd == NULL){
		return 0;
	}else{
		if (G.offline == 0){
			return (G.dev_name==NULL)?0:1;
		}else{
			return (G.read_file==NULL)?0:1;
		}
	}
}

char set_read_file(char *file)
{
	if (file!=NULL){
		if (G.read_file != NULL){
			free(G.read_file);
			G.read_file=NULL;
		}
		G.offline=1;
		G.read_file=(char *)xmalloc(sizeof(char)*(strlen(file)+1));
		strncpy(G.read_file,file,strlen(file));
		G.read_file[strlen(file)]='\0';
		return 0;
	}else{
		log_err(LEVEL2,(char *)"Null file name when set_read_file");
		return -1;
	}
}

char is_offline(void)
{
	return G.offline;
}

int get_fd(void)
{
	
	int dev_fd;
	
	if (G.dev_fd==NULL){
		log_err(LEVEL1,(char *)"Can't get dev_fd");
		return -1;
	}
	dev_fd=pcap_get_selectable_fd(G.dev_fd);

	return dev_fd;
}
/*
int main(int argc, char **argv)
{
	//char *dev = "mon0";
	//char *dev = "mon0";
	
	
	
	//char argv_pcap[3];
	int option_index=0;
	int op;
	
	char list;
	char own_scan;
	  
	static struct sigaction ctrl_c_act;
	
	//uint8_t tmpc;
	//int tmpfd;
	
	
	unsigned int hop_delay;
	
	char no_channels;
	
	pid_t fork_result;
	
	const struct option long_options[] = 
	{

                
		{"read",    required_argument, 0, 'r'},
		{"write",    required_argument, 0, 'w'},
		{"ch",    required_argument, 0, 'c'},
//BETTER LONG NAME?
		{"leave_current",    no_argument, 0, 'L'},
		{"lchann",   no_argument,	0, 'C'},
		{"lfreq",   no_argument,	0, 'F'},
		{"bssid",   required_argument,	0, 'b'},
		{"address",   required_argument,	0, 'a'},
		{"help",   no_argument,	0, 'h'},
		{0, 0, 0, 0}
	};
	
	
	ctrl_c_act.sa_handler=exiting_ctr_c;
	//ctrl_c_act.flags=0;
	
	//

	
	G_init();

	G.start_time=time(NULL);
	option_index = 0;
	no_channels=0;
	
	list=0;
	
	own_scan=0;
	//printf("sizeof:%d",sizeof(useconds_t));
	hop_delay=DEFAULT_HOP_DELAY;
	
	while ((op=getopt_long (argc, argv, "r:w:c:b:a:CFLh",
                            long_options, &option_index))!=-1){
		switch (op){
			case 'r':
				if (set_read_file(optarg) != 0){
					log_err(LEVEL0,(char *)"Error setting read file. Exiting");
					exit(EXIT_FAILURE);
				}
				break;
			case 'w':
				G.dump=1;
				G.write_file=(char *)xmalloc(sizeof(char)*(strlen(optarg)+1));
				strncpy(G.write_file,optarg,strlen(optarg));
				G.write_file[strlen(optarg)]='\0';
				break;
			case 'c':
				own_scan=own_scan | SET_OWN_CHANNEL;
				no_channels=parse_own_channels(optarg);
				if (no_channels==-1 || G.freq==NULL){
					log_err(LEVEL0,(char *)"Channel argument is invalid");
					exit(EXIT_FAILURE);
				}
				break;
			case 'C':
				list=list | LIST_CHANNELS;
				break;
			case 'F':
				list=list | LIST_FREQUENCIES;
				break;
			case 'L':
				own_scan=own_scan | LEAVE_CURRENT_CHANNEL;
				break;
			case 'b':
				
				G.filter=G.filter | FILTER_BSSID;
// 				//try to put opt arg to G.filter_bssid
				if (mac_parse(G.filter_bssid,optarg)!=0){
					log_err(LEVEL0,(char *)"Invalid bssid address");
					exit(EXIT_FAILURE);
				}
				//dbg_mac("BSSID",G.filter_bssid);
				//exit(1);
				break;
			case 'a':
				
				G.filter=G.filter | FILTER_ADDRESS;
// 				//try to put opt arg to G.filter_bssid
				if (mac_parse(G.filter_address,optarg)!=0){
					log_err(LEVEL0,(char *)"Invalid address");
					exit(EXIT_FAILURE);
				}
				//dbg_mac("BSSID",G.filter_bssid);
				//exit(1);
				break;
			case 'h':
				print_usage();
				exit(EXIT_SUCCESS);
				break;
								
			case '?':
//TODO: PRINT USAGE				
				log_err(LEVEL0,(char *)"exiting");
				return EXIT_FAILURE;
				break;
		 }
	
	}
	
	if (argc-optind==1 && G.offline!=1){
		if (strlen(argv[argc-1])>=IFNAMSIZ){
			log_err(LEVEL0,(char *)"Interface name lenght must be at most %d characters",IFNAMSIZ);
			return EXIT_FAILURE;
		}
		set_dev_name(argv[argc-1]);
	}else{
		if (argc-optind>1){
			log_err(LEVEL0,(char *)"Too many opts");
			return EXIT_FAILURE;
		}else{
			//xxx
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!			
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//TREBUIE DECOMENTAT!!!!!!!!!!			
//			if (G.offline!=1){
	//			log_err(LEVEL0,(char *)"No interface specified");
		//		return EXIT_FAILURE;
			//}
		}
	}

	


	
	


	//don't forget to increase size of argc_pcap
	//argv_pcap[0]=pcap_datalink(dev_fd);
	//argv_pcap[1]=G.offline;

	
	
	
	
	
	//exit gracefull when ctrl+c is pressed
	sigaction( SIGINT, &ctrl_c_act, NULL );
	
	//segmentation fault
	sigaction( SIGSEGV, &ctrl_c_act, NULL );
	
	
	atexit(proper_exit);
	
	
		
	
	
	printf("canal:%d",tmpc);
	test=G.dev_fd;
	tmpfd=pcap_get_selectable_fd(G.dev_fd);
	printf("tmpfd:%d",tmpfd);
	
	set_channel(tmpfd,G.dev_name,tmpc);
	exit(1);

	printf("\33[2J");

	
	if (G.offline == 0){
		if (G.dev_name != NULL){
			if (set_interface()!=0){
				log_err(LEVEL0,(char *)"Can't set interface. Exiting");
				exit(EXIT_FAILURE);
			}
		}
	}else{
		if (G.read_file != NULL){
			if (set_interface()!=0){
				log_err(LEVEL0,(char *)"Can't set read interface. Exiting");
				exit(EXIT_FAILURE);
			}
		}
	}
		
		
#if QT_INTERFACE==1
	G.ui=1;
#else
	G.ui=0;
#endif
	//here is happening everything
	
	//G.ui=0;
	if (G.ui==1){
		//pthread_create(&thread2,NULL,qt_interface,NULL);	
		#if QT_INTERFACE==1
			qt_main(argc,argv);
		#else
			log_err(LEVEL1,"You don't have QT!");
			exit(EXIT_FAILURE);
		#endif
	}else{
		

		if (G.dev_fd==0){
			//if (G.)
			log_err(LEVEL0,(char *)"No interface specified");
			exit(EXIT_FAILURE);
		}
		//!BUG 3 (labeled as)
			//!we are not checking if card could be set in monitor mode
		
			if (pcap_set_rfmon(dev_fd,1)!=0){
				log_err(LEVEL0,"%s could not be set in monitor mode. You should install proper driver %d ",dev,pcap_set_rfmon(dev_fd,1));
				return EXIT_FAILURE;
			}
		
	
	
		if (list!=0){
			console_list(list);
			exit(EXIT_SUCCESS);
		}
	
	
		if (init_scan_freq(own_scan,&no_channels) != 0){
			log_err(LEVEL0,(char *)"Can't init freq. Exiting");
			exit(EXIT_FAILURE);
		}
	
	
	
				
				
				
	
		if (G.dump==1){
			G.write_fd=pcap_dump_open(G.dev_fd, G.write_file);
			if (G.write_fd==NULL){
				log_err(LEVEL0,(char *)"Couldn't open file %s for writing: %s",G.write_file,pcap_geterr(G.dev_fd)); 
				return EXIT_FAILURE;
			}
		}
		
		//G.freq must be filled in this step
		if (no_channels>0){
			if (no_channels==1){
				set_freq(G.freq[0]);
			}else{
				fork_result=fork();
				if (fork_result==-1){
					log_err(LEVEL0,(char *)"Can't fork: %s",strerror(errno));
					exit(EXIT_FAILURE);
				}
				
				if (fork_result==0){
					G.child=G.child | CHILD_HOP_FREQ;
				}
			}
		}




		//true only in child
		if ((G.child & CHILD_HOP_FREQ)!=0){
			
			//loop_forever
			freq_hop(hop_delay);
			exit(EXIT_FAILURE);
			
		}
		
		
		main_loop(NULL);
		
	}
	


	return EXIT_SUCCESS;
}	
*/





/*
		if (G.offline==1){
			packet = pcap_next(G.dev_fd, &header);
			if (packet==NULL){
				log_err(LEVEL1,"Read failed:%s datalink:%d",pcap_geterr(G.dev_fd),G.datalink);
			}else{
				got_pkg(NULL,&header,packet);
			}
		}else{
*/

