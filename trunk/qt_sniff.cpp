#include <QProgressDialog>
#include <errno.h>
#include <pthread.h>
#include <pcap/pcap.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "qt_common.h"
#include "qt_snif.h"
#include "common.h"
#include "sniffer.h"




MySniff::MySniff(QWidget *parent)
{
	this->parent = parent;

	this->init();
	
	this->crack = new MyCrack(parent);
	
}

void MySniff::init()
{
	status = TH_STOPPED;
	settings = 0;
	if (is_dev_set() == 1){
		settings = settings | XSNIFF_SETTING_IS_SET_INTERFACE;
	}
}


unsigned char MySniff::can_start()
{
	if (status == TH_STOPPED){
		if (is_dev_set() == 1){
			return 1;
		}else{
			return 0;
		}
	}else{
		return 0;
	}
	
}

unsigned char MySniff::can_stop()
{
	return  (status == TH_STARTED)?1:0;
}

char MySniff::start()
{	
	if (status != TH_STOPPED){
		xlog_err(LEVEL9,parent,"Alert","Capture is already started");
		return -1;
	}
	
	if ((settings & XSNIFF_SETTING_IS_SET_INTERFACE) == 0){
		xlog_err(LEVEL2,parent,"Alert","Interface is not set!");
		return -1;
	}
	
	if (is_offline() == 0){
		if ((settings & XSNIFF_SETTING_IS_SET_FREQ) == 0){
			if (this->cfg_chann()!=0){
				xlog_err(LEVEL2,parent,"Alert","Can't run start without channel initialisation!");	
				return -1;
			}
		}
	}
	
	if (is_everything_set()!=0){
		xlog_err(LEVEL2,parent,"Alert","Can't start. Error: %d",is_everything_set());
		return -1;
	}
	
	if (pthread_create(&th_start_capture,NULL,main_loop,NULL) != 0){
		log_err(LEVEL1,(char *)"Can't create thread: %s",(char *)strerror(errno));
		xlog_err(LEVEL1,parent,"Alert","Can't create thread: %s",(char *)strerror(errno));
		return -1;
	}else{
		status = TH_STARTED;
		//pthread_join(th_start_capture,&value_ptr);
		
		if (is_offline() == 0){
			if (this->start_hop_freq() != 0){
				xlog_err(LEVEL2,parent,"Warning","Capture started but will listen only on current channel");
			}
		}
		
		return 0;
	}
}

char MySniff::start_offline()
{
	
	
	int pcap_fd;
	struct stat sb;	
	
	/*
	if ((pcap_fd=get_fd())<0){
		xlog_err(LEVEL1,parent,"Alert","Can't open file (start_offline)");
		return -1;
	}
	
	
	if (fstat(pcap_fd,&sb)!=0){
		xlog_err(LEVEL1,parent,"Alert","Can't get file attributes: %s",(char *)strerror(errno));
		return -1;
	}
	
	if (sb.st_mode==S_IFLNK){
		xlog_err(LEVEL1,parent,"BUG","You should not be here! File is a symlink!");
		return -1;
	}
	
	//sb.st_size	
	*/	
	if (status != TH_STOPPED){
		//this->stop();
		xlog_err(LEVEL2,parent,"Alert","Can't be here (start_offline()  status=TH_STARTED");
		return -1;
	}
	
	//if (pthread_create(&th_start_capture,NULL,main_loop,NULL) != 0){
	//	log_err(LEVEL1,(char *)"Can't create thread: %s",(char *)strerror(errno));
	//	xlog_err(LEVEL1,parent,"Alert","Can't create thread: %s",(char *)strerror(errno));
		//return -1;
	//}
	
	//xlog_err(LEVEL2,parent,"Alert","OK");
	this->start();
	//xlog_err(LEVEL2,parent,"Alert","status %d",status);
		
	/*
	char *value;
	
	int x;
	
	x=pthread_join(th_start_capture,(void **)&value);
	
	
	this->soft_stop();
	
	
	if (value!=NULL){
		xlog_err(LEVEL2,parent,"Alert",value);
		free(value);
	}
	//progress_bar->setValue(100);
	//progress_bar->done(0);
	//	xlog_err(LEVEL1,parent,"BUG","Ok! %d",x);
	
	
	
	//x = new QProgressDialog(parent);
	//x = new QProgressDialog("Operation in progress.", "Cancel", 0, 100,parent);
	
	this->start();
	QProgressDialog progress("Copying files...", "Abort Copy", 0, 100, parent);
		progress.setWindowModality(Qt::WindowModal);
   
		for (int i = 0; i < 50; i++) {
			progress.setValue(i);
			
		//	if (progress.wasCanceled())
		//		break;
			//... copy one file
		}
	//	progress.setValue(numFiles);
	*/
	return 0;
}

///???????????????????????????????????????????????????
void MySniff::soft_stop()
{
	status = TH_STOPPED;
	
	if ((settings & XSNIFF_SETTING_HOP_FREQ) != 0){
		if (this->stop_hop_freq() != 0){
			xlog_err(LEVEL2,parent,"Warning","Capture stopped but it is a problem with stopping frequencies change");
		}
	}
	
	stop_clean();

}

char MySniff::stop()
{
	int thret;
	if (status == TH_STOPPED){
		xlog_err(LEVEL9,parent,"Alert","Capture is already stopped");
		return -1;
	}
	
	
	if ((thret=pthread_cancel(th_start_capture)) != 0){
		if (thret!=ESRCH){
			xlog_err(LEVEL7,parent,"Alert","Can't stop thread: %s",(char *)strerror(errno));
			return -1;
		}else{
			status = TH_STOPPED;
			log_err(LEVEL10,(char *)"XAlert (warning): Thread already stopped");
			
			if ((settings & XSNIFF_SETTING_HOP_FREQ) != 0){
				if (this->stop_hop_freq() != 0){
					xlog_err(LEVEL2,parent,"Warning","Capture stopped but it is a problem with stopping frequencies change");
				}
			}
			stop_clean();
			
			return 0;
		}
	}else{
		status = TH_STOPPED;
		
		if ((settings & XSNIFF_SETTING_HOP_FREQ) != 0){
			if (this->stop_hop_freq() != 0){
				xlog_err(LEVEL2,parent,"Warning","Capture stopped but it is a problem with stopping frequencies change");
			}
		}
		
		stop_clean();
		return 0;
	}
}

char MySniff::try_stop()
{
	if (this->status == TH_STARTED)
		return this->stop();	
	else
		return 0;
}

char MySniff::start_hop_freq()
{	
	
	if ((settings & XSNIFF_SETTING_IS_SET_INTERFACE) == 0){
		xlog_err(LEVEL2,parent,"Alert","Can't hop freq interface is not set!");
		return -1;
	}
	
	if ((settings & XSNIFF_SETTING_IS_SET_FREQ) == 0){
		xlog_err(LEVEL2,parent,"BUG","Can't hop freq without channel initialisation!");	
		return -1;
	}
	
	if (pthread_create(&th_hop_freq,NULL,main_hop,NULL) != 0){
		log_err(LEVEL1,(char *)"Can't create thread (qt-hop-freq): %s",(char *)strerror(errno));
		xlog_err(LEVEL1,parent,"Alert","Can't create thread (qt-hop-freq): %s",(char *)strerror(errno));
		return -1;
	}else{
		
		settings = settings | XSNIFF_SETTING_HOP_FREQ;
		return 0;
	}
}

char MySniff::stop_hop_freq()
{	
	
	if ((settings & XSNIFF_SETTING_HOP_FREQ) == 0){
		xlog_err(LEVEL1,parent,"Bug","Can't stop hop_freq (not started)");
	}
	
	if (pthread_cancel(th_hop_freq) != 0){
		log_err(LEVEL10,(char *)"Can't stop thread (qt-hop-freq): %s",(char *)strerror(errno));
		xlog_err(LEVEL1,parent,"Alert","Can't stop thread (qt-hop-freq): %s",(char *)strerror(errno));
		settings = settings & (~XSNIFF_SETTING_HOP_FREQ);
		return -1;
	}else{
		settings = settings & (~XSNIFF_SETTING_HOP_FREQ);
		return 0;
	}
}
	

char MySniff::cfg_read_fname(char *file_name)
{
	if (this->status==TH_STARTED){
		this->stop();
	}
	
	if (this->status==TH_STOPPED){
		new_dev_clean();
		
		if (file_name==NULL){
			xlog_err(LEVEL2,parent,"Alert","Null file name");
			return -1;
		}	
		if (set_read_file(file_name) != 0){
			xlog_err(LEVEL2,parent,"Alert","Can't set read file name");
			return -1;
		}
		
		if (set_interface() < 0){
			xlog_err(LEVEL2,parent,"Alert","Can't read data from %s",file_name);
			return -1; 
		}
		
		settings = settings | XSNIFF_SETTING_IS_SET_INTERFACE;
		return 0;
	}else{
		xlog_err(LEVEL2,parent,"Alert","Can't stop thread, before starting a new one (in read)");
		return -1;		
	}	
	

	
}

char MySniff::cfg_interface(char *name)
{
	new_dev_clean();
	set_dev_name(name);
	if (set_interface()<0){
		xlog_err(LEVEL2,parent,"Alert","This is not an supported wireless device. Check if the device is wireless and you have enabled monitor mode");
		return -1; 
	}
	
//TODO 	we should use G.freq and not default one
	
	settings = settings | XSNIFF_SETTING_IS_SET_INTERFACE; 
	
	if (is_offline() == 0){
		if (this->cfg_chann()!=0){
			xlog_err(LEVEL7,parent,"Alert","Please set custom channels before start capturing");
			//return -1;
			//!?
		}
	}
	
	return 0;
}

char MySniff::cfg_chann(char *channels)
{
	int tmp;
	uint8_t default_channels[]=
	{
		1, 7, 13, 2, 8, 3, 9, 4, 10, 5, 11, 6, 12, 0
		//1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0
	};
	
	if (is_offline() != 0){
		xlog_err(LEVEL1,parent,"Alert","Can't set channels in offline mode");
		return -1;
	}
	
	if ((settings & XSNIFF_SETTING_IS_SET_INTERFACE) == 0){
		xlog_err(LEVEL2,parent,"Alert","First you must configure interface!");
		return -1;
	}
	
	if (channels==NULL){
		if (init_default_channels(default_channels) < 0){
			xlog_err(LEVEL2,parent,"Alert","Can't init default channels");
			return -1;
		}
		
	}else{
		if (parse_own_channels(channels)<0){
			xlog_err(LEVEL2,parent,"Alert","Can't parse channels. You must enter just positive numbers (lower than 255) and comas Eg: 1,2,3,4,5");
			return -1;
		}
	}
	
	tmp=verify_freq();
	if (tmp!=0){
		if (tmp>0){
			xlog_err(LEVEL2,parent,"Alert","Unsuported channel %d (%d MHz)",get_channel(tmp-1),get_freq(tmp-1));
			return -1;
		}else{
			xlog_err(LEVEL2,parent,"Alert","Can't set channels");
			return -1;
		}
	}
		
	settings = settings | XSNIFF_SETTING_IS_SET_FREQ; 
	
	return 0;
	
}

char MySniff::cfg(char *interface_name,char *channels)
{
	if (this->cfg_interface(interface_name) != 0){
		return -1;
	}
	
	if (this->cfg_chann(channels) != 0){
		return -1;
	}
	
	return 0;
	
}



char MySniff::settings_is_freq_set()
{
	return ((settings & XSNIFF_SETTING_IS_SET_FREQ)!=0)?1:0;
}

char MySniff::clear_all()
{

	if (status != TH_STOPPED){
		xlog_err(LEVEL6,parent,"Alert","You must stop capture before clearing all data");
		return -1;
	}
	
	main_clean();
	this->init();
	
	return 0;
}

char MySniff::clear_ap()
{
	if (status != TH_STOPPED){
		xlog_err(LEVEL6,parent,"Alert","You must stop capture before clearing all data");
		return -1;
	}

	ap_clean();	
	return 0;
}

char MySniff::is_all_set()
{
	return is_everything_set();
}

QString MySniff::get_current_channels(void)
{
	QString chn("");
	
	uint16_t *freqs;
			
	freqs=current_freq();
	
	if (freqs!=NULL){
		while (*freqs!=0){
			chn.append(QString::number(ieee80211mhz2chan(*freqs)));
			freqs++;
			if (*freqs!=0){
				chn.append(",");		
			}
		}
	}
	return chn;
}
char MySniff::get_status(void)
{
	return this->status;
}
/*
MySniff::~MySniff()
{
	xlog_err(LEVEL6,parent,"BUG","Destruct of MySniff");
	log_err(LEVEL0,"Destruct of MySniff");
}

*/
