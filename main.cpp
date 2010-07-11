#include <getopt.h>
#include <signal.h>
#include <sniffer.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <errno.h>

#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/wireless.h>

#if QT_INTERFACE==1
	#include "qt_interface.h"
#endif

#include "sniffer.h"
#include "xmalloc.h"


extern struct global_variables G;

//WE should do more than that!!!
//Close interface fd,readfd, free memory etc
void exiting_ctr_c(int x)
{

	if (G.child==0){
		//printf("\33[?1l");	
		//printf("\n\n\n\n\n\nLALALALALA\n\n\n\n\n\n\n");
		if (G.dump==1){
			if (G.write_fd!=NULL){
				pcap_dump_flush(G.write_fd);
				pcap_dump_close(G.write_fd);
				G.write_fd=NULL;
				G.dump=0;
			}
		}
		
		main_clean();

		exit(EXIT_SUCCESS);
	}else{
		//must remove this warning
		log_err(LEVEL10,(char *)"Call to proper exit in child");
	}
}

void proper_exit(){
	//printf("\n\n\n\n\n\nproper exit\n\n\n\n\n\n\n");
	//if (G.dump==1){
	//	G.dump=0;
		exiting_ctr_c(0);
		
	//}
}


void print_usage(){

	char usage[]=
		"\nusage: %s <options> <interface>\n\n"
		"Options:\n"
		"  -r, --read <file> 	: Reads packets from a file (offline mode)\n"
		"  -w, --write <file> 	: Writes captured packets to a file\n"
		"  -c, --ch <channels>	: Capture packets just from given channels\n"
		"  -L, --leave_current	: Don't hop channels\n"
		"  -C, --lchann		: List supported channels\n"
 		"  -F, --lfreq		: List supported frequencies\n"
		"\n"
		"Filter options:\n"
		" -b, --bssid <bssid>	: Filter captured packets by bssid\n"
		" -a, --addr <address>	: Filter captured packets by address\n"
		"\n";
		
	printf(usage,"sniff");
}



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
	
	
		
	
/*	
	printf("canal:%d",tmpc);
	test=G.dev_fd;
	tmpfd=pcap_get_selectable_fd(G.dev_fd);
	printf("tmpfd:%d",tmpfd);
	
	set_channel(tmpfd,G.dev_name,tmpc);
	exit(1);

	printf("\33[2J");
*/	
	
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
		/*
			if (pcap_set_rfmon(dev_fd,1)!=0){
				log_err(LEVEL0,"%s could not be set in monitor mode. You should install proper driver %d ",dev,pcap_set_rfmon(dev_fd,1));
				return EXIT_FAILURE;
			}
		*/	
	
	
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
