#ifndef ___SNIFFER_H___
#define ___SNIFFER_H___


#include <stdint.h>
#include <pcap.h>
#include <unistd.h>
#include "common.h"








#define DEBUG_MODE 1
#define APP_NAME "sair"


#define DEFAULT_HOP_DELAY 200 //period of time when frequency must be changed (ms) 


/*?*/
#define ETHERNET_SIZE 16

#define IEEE80211_SUPORTED_VERSION 0



/*type of IEEE802.11 frames */
#define IEEE80211_FRAME_MANAGEMENT 0
#define IEEE80211_FRAME_CONTROL 1
#define IEEE80211_FRAME_DATA 2




/* type_subtype From IEEE std 802.11 VERSION 0 */
#define IEEE80211_FRAME_MANAGEMENT_ASSOS_REQ 0x00
#define IEEE80211_FRAME_MANAGEMENT_ASSOS_RESP 0x01
#define IEEE80211_FRAME_MANAGEMENT_REASSOS_REQ 0x02
#define IEEE80211_FRAME_MANAGEMENT_REASSOS_RESP 0x03
#define IEEE80211_FRAME_MANAGEMENT_PROBE_REQ 0x04
#define IEEE80211_FRAME_MANAGEMENT_PROBE_RESP 0x05
#define IEEE80211_FRAME_MANAGEMENT_BEACON 0x08 //test
#define IEEE80211_FRAME_MANAGEMENT_ATIM 0x09
#define IEEE80211_FRAME_MANAGEMENT_DISSASOC 0x0A
#define IEEE80211_FRAME_MANAGEMENT_AUTH 0x0B
#define IEEE80211_FRAME_MANAGEMENT_DEAUTH 0x0C
#define IEEE80211_FRAME_MANAGEMENT_ACTION 0x0D
#define IEEE80211_FRAME_CONTROL_BLOCKACKREQ 0x18
#define IEEE80211_FRAME_CONTROL_BLOCKACK 0x19
#define IEEE80211_FRAME_CONTROL_PSPOLL 0x1A
#define IEEE80211_FRAME_CONTROL_RST 0x1B
#define IEEE80211_FRAME_CONTROL_CST 0x1C
#define IEEE80211_FRAME_CONTROL_ACK 0x1D
#define IEEE80211_FRAME_CONTROL_CFEND 0x1E
#define IEEE80211_FRAME_CONTROL_CFEND_CFACK 0x1F
#define IEEE80211_FRAME_DATA_DATA 0x20
#define IEEE80211_FRAME_DATA_DATA_ACK 0x21
#define IEEE80211_FRAME_DATA_DATA_CFPOOL 0x22
#define IEEE80211_FRAME_DATA_DATA_CFACK_CFPOLL 0x23
#define IEEE80211_FRAME_DATA_NULL 0x24 //no data
#define IEEE80211_FRAME_DATA_CFACK 0x25 //no data
#define IEEE80211_FRAME_DATA_CFOLL 0x26 //no data
#define IEEE80211_FRAME_DATA_CFACK_CFPOLL 0x27 //no data
#define IEEE80211_FRAME_DATA_QOS_DATA 0x28
#define IEEE80211_FRAME_DATA_QOS_DATA_CFACK 0x29
#define IEEE80211_FRAME_DATA_QOS_DATA_CFPOLL 0x2A
#define IEEE80211_FRAME_DATA_QOS_DATA_CFACK_CFPOLL 0x2B
#define IEEE80211_FRAME_DATA_QOS_NULL 0x2C //no data
#define IEEE80211_FRAME_DATA_QOS_CFPOLL 0x2E //no data
#define IEEE80211_FRAME_DATA_QOS_CFACK_CFPOLL 0x2F //no data


/* MAC LENGTH HEADER for FRAMES (octets)*/
#define IEEE80211_FRAME_CONTROL_RST_H_SIZE 16
#define IEEE80211_FRAME_CONTROL_CST_H_SIZE 10
#define IEEE80211_FRAME_CONTROL_ACK_H_SIZE 10
#define IEEE80211_FRAME_CONTROL_PSPOLL_H_SIZE 16
#define IEEE80211_FRAME_CONTROL_CFEND_CFACK_H_SIZE 16
#define IEEE80211_FRAME_CONTROL_BLOCKACKREQ_H_SIZE 16
#define IEEE80211_FRAME_CONTROL_BLOCKACK_H_SIZE 16
#define IEEE80211_FRAME_DATA_NO_ADDR4_H_SIZE 24 //header for data frame with flags DS=0,1,2
#define IEEE80211_FRAME_DATA_W_ADDR4_H_SIZE 30 //header for data frame with flags DS=3
#define IEEE80211_FRAME_DATA_W_QOS_H_SIZE 32 // header for data frame with QoS bit=1
#define IEEE80211_FRAME_CONTROL_CFEND_H_SIZE 16
#define IEEE80211_FRAME_MANAGEMENT_H_SIZE 24


//element id 
//length for element id
//SSID
#define IEEE802_INF_ELEMENT_SSID 0
#define IEEE802_INF_ELEMENT_SSID_MAX_LEN 32

//DS
#define IEEE802_INF_ELEMENT_DS 3
#define IEEE802_INF_ELEMENT_DS_MAX_LEN 1

//RSN
#define IEEE802_INF_ELEMENT_RSN 0x30
#define IEEE802_INF_ELEMENT_RSN_VERSION 0x0100 //Don't increment, change the code!
#define IEEE802_INF_ELEMENT_RSN_MAX_LEN 255
//RSN CIPHER
#define IEEE802_INF_ELEMENT_RSN_CIPHER_GROUP 0x000FAC00
#define IEEE802_INF_ELEMENT_RSN_CIPHER_WEP40 0x000FAC01
#define IEEE802_INF_ELEMENT_RSN_CIPHER_TKIP 0x000FAC02
#define IEEE802_INF_ELEMENT_RSN_CIPHER_CCMP 0x000FAC04
#define IEEE802_INF_ELEMENT_RSN_CIPHER_WEP104 0x000FAC05

//RSN AKM
#define IEEE802_INF_ELEMENT_RSN_AKM_RSNA 0x000FAC01
#define IEEE802_INF_ELEMENT_RSN_AKM_PSK 0x000FAC02
//#define IEEE802_INF_ELEMENT_RSN_AKM_PSK


//information element vendor
#define IEEE802_INF_ELEMENT_VENDOR 0xDD
#define IEEE802_INF_ELEMENT_VENDOR_VERSION 0x0100 //NOT USED!!!! see bug 7
#define IEEE802_INF_ELEMENT_VENDOR_OUI 0x0050F201
#define IEEE802_INF_ELEMENT_VENDOR_CIPHER_GROUP 0x0050F200
#define IEEE802_INF_ELEMENT_VENDOR_CIPHER_WEP40 0x0050F201
#define IEEE802_INF_ELEMENT_VENDOR_CIPHER_TKIP 0x0050F202
#define IEEE802_INF_ELEMENT_VENDOR_CIPHER_CCMP 0x0050F204
#define IEEE802_INF_ELEMENT_VENDOR_CIPHER_WEP104 0x0050F205
#define IEEE802_INF_ELEMENT_VENDOR_AKM_RSNA 0x0050F201
#define IEEE802_INF_ELEMENT_VENDOR_AKM_PSK 0x0050F202


//CAPABILITY 
#define CAPABILITY_WEP 0x0010

//cipher types
#define CIPHER_NULL 0x0000
#define CIPHER_GRP 0x0001
#define CIPHER_WEP40 0x0002
#define CIPHER_TKIP 0x0004
#define CIPHER_CCMP 0x0008
#define CIPHER_WEP104 0x0010
#define CIPHER_PROPRIETARY 0x0020
#define CIPHER_WEP 0x0040
#define CIPHER_OPN 0x0080
#define CIPHER_ENC 0x0100


//auth types
#define AUTH_NULL 0x00
#define AUTH_RSNA 0x01
#define AUTH_PSK 0x02
#define AUTH_PROPRIETARY 0x04


//used in counting frames
#define NO_MANAGEMENT 0x80
#define NO_BEACON 0x40
#define NO_CONTROL 0x20
#define NO_DATA 0x10

#define DEBUG_FOLDER "/tmp"

#define BEACON_FIXED_PARAM_LEN 12 //(octets)


#define STR_BUFFER_SIZE 128 //max len for str_mk




//hw addr
#define MAC_LEN 6 //partialy implemented!!!!
#define HW_ADDR_SIZE MAC_LEN //same thing 


//marked as BUG 5
#define JAPAN_FREQ_UNSUPORTED_MIN 5035
#define JAPAN_FREQ_UNSUPORTED_MAX 5080


#define LIST_CHANNELS 0x01
#define LIST_FREQUENCIES 0x02

#define SET_OWN_CHANNEL 0x01
#define SET_OWN_FREQUENCIES 0x02
#define LEAVE_CURRENT_CHANNEL 0x04

#define CHILD_HOP_FREQ 0x01



#define MAX_NO_CHANNELS 255 //to protect from forever loop

#define PASSCODE_MAX 64 //length ok maxim passcode
#define PASSCODE_MIN 8

#define FILTER_BSSID 0x0001
#define FILTER_ADDRESS 0x0002
 
 
#define LLC_SNAP_SIZE 8
 
//EAPOL FRAMES 
//key info low byte 
#define AUTH_EAPOL_PARSE_KEY_LOW_INFO_VERSION 0x03
#define AUTH_EAPOL_PARSE_KEY_LOW_TYPE 0x08
#define AUTH_EAPOL_PARSE_KEY_LOW_ACK 0x80
//key info high byte
#define AUTH_EAPOL_PARSE_KEY_HI_MIC 0x01
#define AUTH_EAPOL_PARSE_KEY_HI_SECURE 0x02
#define AUTH_EAPOL_PARSE_KEY_HI_ERROR 0x04
 
//used in eapol messages
#define AUTH_SUPPORTED_VERSION1 1
#define AUTH_SUPPORTED_VERSION2 2

#define AUTH_SUPPORTED_TYPE 0x03
 
//eapol NOUNCE size 
#define AUTH_NONCE_SIZE 32
#define AUTH_EAPOL_SIZE_MAX 256

#define AUTH_LENGTH_OFFSET 4
#define AUTH_MIC_OFFSET 81
#define AUTH_MIC_SIZE 16

#define  EAPOL_STATE1 0x01
#define  EAPOL_STATE2 0x02
#define  EAPOL_STATE3 0x04
#define  EAPOL_STATE4 0x08



//error codes 
#define ERR_DEV_NAME_NOT_FOUND -1
#define ERR_READ_FILE_NOT_FOUND -2
#define ERR_DEV_DF_NOT_FOUND -3
#define ERR_WRITE_FILE_NOT_FOUND -4
#define ERR_WRITE_FD_NOT_FOUND -5


//max error messages from cracking
#define ERROR_MAX 64

//errors for cracking
#define ERR_DICT_CANT_OPEN -1
#define ERR_DICT_AP_NULL -2
#define ERR_DICT_PASS_NULL -3
#define ERR_DICT_NO_EAPOL -4
#define ERR_DICT_CANT_READ -5
#define ERR_DICT_CANT_READ_LINE -6







 
#define QT_INTERFACE 1



#ifdef __cplusplus
extern "C" {
#endif



 
//stores eapol frames
//see wpa_init
struct wpa_eapol{
	uint8_t version;
	uint8_t anonce[AUTH_NONCE_SIZE];
	uint8_t snonce[AUTH_NONCE_SIZE];
	uint8_t stmac[HW_ADDR_SIZE];
	uint8_t state;
	time_t last_seen;
	uint8_t eapol[AUTH_EAPOL_SIZE_MAX];
	int eapol_size;
	uint8_t mic[AUTH_MIC_SIZE];
	
};
 
 
//part of util informations from pkg
//every new variable should be initialised in rd_init
//every variable dynamic allocated must be deallocated in rd_destroy
struct pkg_util_info{
//	int enc;
	unsigned int max_rate;
	uint8_t channel; //bit 7 is 1 when channel is determined from radiotap
	int signal;
	int noise;    
	char protocol; // frame control version
	char type; //frame control type
	char subtype; //frame control subtype
	char type_subtype; 
	char flag_ds; //see below
	char is_protected; //1 if data is protected 
	uint8_t da[6]; //destination address
	uint8_t sa[6]; //source address
	uint8_t bssid[6]; //bssid address
//future: uint8_t addr4[6]; // when address 4 is activates
	char ssid[IEEE802_INF_ELEMENT_SSID_MAX_LEN+1];
	time_t seen;
	uint8_t no; //user for number of different frames 
	uint16_t cipher;
	uint8_t auth;
	struct wpa_eapol *wpa;
};


//see ap_add and ap_update
struct access_point{
	uint8_t bssid[6];
	struct access_point *prev;
	struct access_point *next;
	char *ssid;
	uint8_t max_rate;
	uint8_t *bsstime;
	time_t fseen;
	time_t lseen;
	unsigned int no_clients;
	struct client *clients;
	unsigned char type;
	uint8_t channel; //bit 7 is 1 when channel is determined from radiotap
	unsigned char privacy;
	unsigned char encrypted;
	unsigned int no_pkg; //number of packets
	unsigned int no_beacon; //number of beacons
	unsigned int no_management; //number of management packets
	unsigned int no_data; //number of data packets
	unsigned int no_control; //number of control frames
	int signal_power;
	int signal_noise;
	uint16_t cipher;
	uint8_t auth;
	struct wpa_eapol *wpa; //did we recieve a handshake
	struct wpa_eapol *wpa_new; //temporary structure waiting for a new handshake 
				   //(note that if only first two messages from eapol are recieved struct wpa_eapol *wpa is not updated)
				   //(so you shoud check also this structure for partially handshake if wpa is NULL)
	uint16_t id; //incremental value used for faster display, when using GUI 
				 //if you change the type don't forget to update struct crack
};
	

struct th_crack{
	const struct access_point *ap;
	//char pass[PASSCODE_MAX];
	char *fname;
};


struct client{
	struct access_point *ap;
	uint8_t addr[6];
	struct client *prev;
	struct client *next;
	uint8_t maxrate; 
	uint8_t *bsstime;
	time_t fseen;
	time_t lseen;
	unsigned int no_clients;
	struct client *clients;
	unsigned char type;
	uint8_t channel; //bit 7 is 1 when channel is determined from radiotap
	unsigned char privacy;
	unsigned char encrypted;
	unsigned int no_pkg; //number of packets
	unsigned int no_beacon; //number of beacons
	unsigned int no_management; //number of management packets
	unsigned int no_data; //number of data packets
	unsigned int no_control; //number of control frames
	int signal_power;
	int signal_noise;

};


/*
IEEE802.11 version 0

+---------------------------------------------------------------------------------------+
|     frame_type 8 bits     |                       flags ( 8 bits )                    |
+----------+------+---------+----+------+------+-------+-----+------+-----------+-------+
| Protocol | Type | Subtype | To | From | More | Retry | Pwr | More | Protected | Order | 
| version  |	  |         | Ds | Ds   | Flag |       | Mgt | Data | Frame     |       | 
+----------+------+---------+----+------+------+-------+-----+------+-----------+-------+
|  2 bits  | 2 b  | 2 bits  | 1b |  1b  |  1b  | 1 bit |  1b |  1b  |   1 bit   | 1 bit |
+----------+------+---------+----+------+------+-------+-----+------+-----------+-------+

*/
struct ieee80211_frame{
	uint8_t frame_type;  //including protocol version,type and subtype 
	uint8_t flags; // 
	uint16_t duration;
	uint8_t addr1[6];
	uint8_t addr2[6];
	uint8_t addr3[6];
	uint16_t seq_cntrl; //fragment+sequence 
	uint8_t addr4[6];
	uint16_t qos_cntrl; //Just where subtype is QoS 
};




//used for management frames
struct information_element {
	const u_char *frame_body;
	unsigned int frame_length;
	unsigned int crt_index;
	uint8_t tag_number;
	uint8_t tag_len;
	uint8_t *tag_info;
};


struct llc_snap{
	uint8_t dsap;
	uint8_t ssap;
	uint8_t ctl;
	uint8_t oui[3];
	uint8_t type_hi;
	uint8_t type_low;
};


struct auth_80211{
	uint8_t version;
	uint8_t type;
	uint8_t length_hi;
	uint8_t length_low;
	uint8_t descr_type;
	uint8_t key_info_hi;
	uint8_t key_info_low;
	uint8_t key_length_hi;
	uint8_t key_length_low;
	uint8_t replay_counter[8];
	uint8_t nonce[AUTH_NONCE_SIZE];
	uint8_t keyiv[16];
	uint8_t wpa_key_rsc[8];
	uint8_t wpa_key_id[8];
	uint8_t wpa_key_mic[AUTH_MIC_SIZE];//8??
	uint8_t wpa_key_length_hi;
	uint8_t wpa_key_length_low;
};
	
	


//RSN information (information element)
/*struct information_element_RSN {
	
	uint8_t element_id;
	uint8_t length;
	uint16_t version;
	
	
	const u_char *frame_body;
	unsigned int frame_length;
	unsigned int crt_index;
	uint8_t tag_number;
	uint8_t tag_len;
	uint8_t *tag_info;
};
*/





//ALL global variables
struct global_variables{

	struct access_point *lap,*fap; //all access points found
	
	char offline; //if we must read from a file
	char *read_file; //name of the file 
	
	char dump; //if we must write our results in a file
	char *write_file; //name of the file where we should write
	
	char *dev_name; //name of the device

	pcap_t *dev_fd; //fd of the open device
	
	pcap_dumper_t *write_fd; //fd of file for write
	
	int datalink; //pcap_datalink
	
	time_t start_time; //time when app has started
	

//	uint8_t *channel; //list with channels that will be scanned
	uint16_t *freq;    //list with channels that will be scanned
	uint8_t ui; //user interface
	
	
	uint16_t filter;
	uint8_t filter_bssid[6];
	uint8_t filter_address[6];
	
	
	
#if DEBUG_MODE==1
	const struct pcap_pkthdr *dbg_header;	/* The header that pcap gives us */
	const u_char *dbg_packet;		/* The actual packet */
	char child;
#endif
	
};






//Header :P
//must be moved in final version
#if DEBUG_MODE==1	
	void debug(void);
#endif

void *main_loop(void *argv);	
uint8_t *get_supported_channels(void);
uint16_t *get_supported_freq(void);
char mac_equal(const uint8_t dest[MAC_LEN],const uint8_t src[MAC_LEN]);
void set_dev_name(char *name);
void free_dev_name(void);
char set_interface(void);
char is_everything_set(void);

int parse_own_channels(char *channels);
int verify_freq();
int get_channel(int index);
int get_freq(int index);
int init_default_channels(uint8_t *channels);
uint16_t *current_freq(void);
void stop_clean(void);
void new_dev_clean(void);
void *main_hop(void *argv);

void log_err(int debug_level,char *fmt, ...);
void main_clean(void);
void str_add(char str[MAX_STR_TO_DISPLAY],char *toadd);
void str_enc(char str[MAX_STR_TO_DISPLAY],uint16_t cipher);
void str_enc_auth(char str[MAX_STR_TO_DISPLAY],uint8_t auth);
uint8_t is_dev_set(void);
void ap_clean(void);
char is_offline(void);
char set_read_file(char *file);
int get_fd(void);
unsigned char is_part_handshake(const struct access_point *ap);
int try_dict(const char *fname,const struct access_point *ap,char pass[PASSCODE_MAX]);
void *crack_thread(void *argv);
const struct access_point *get_fap(void);
const struct access_point *get_iap(uint16_t index);
void G_init(void);
char mac_parse(uint8_t dest[MAC_LEN],char *src);
int console_list(char list);
int init_scan_freq(char own_scan,char *no_channels);
int set_freq(uint16_t freq);
void freq_hop(useconds_t delay);


#ifdef __cplusplus
}
#endif

#endif
