#ifndef QT_SNIF_H
#define QT_SNIF_H

#include <QProgressDialog>
#include <unistd.h>
#include "qt_crack.h"

//status
#define TH_STOPPED 0
#define TH_STARTED 1


//settings
#define XSNIFF_SETTING_IS_SET_INTERFACE 0x01
#define XSNIFF_SETTING_IS_SET_FREQ 0x02
#define XSNIFF_SETTING_HOP_FREQ 0x04
//#define XSNIFF_SETTING_IS_OFFLINE 0x08


class MySniff //: QWidget
{
//		Q_OBJECT

public:
	MyCrack *crack;

	
private:
	pthread_t th_start_capture;
	pthread_t th_hop_freq;
	char status;
	char settings;
	QWidget *parent;

	

	
	unsigned char can_stop(void);
	void init(void);

	char cfg(char *interface_name,char *channels=NULL);
	char settings_is_freq_set(void);
	void settings_set_freq(void);
	char start_hop_freq(void);
	char stop_hop_freq(void);	
	
	
	//false stop!
	void soft_stop(void);

	
public:
	MySniff(QWidget *parent);
	//~MySniff();
	//int get_status();
	//void set_status(int status);
	char start(void);
	char start_offline(void);
	char stop(void);
	char try_stop(void);	


	
	
	char cfg_interface(char *name);
	char cfg_chann(char *channels=NULL);
	char cfg_read_fname(char *file_name);
	char clear_all(void);
	char clear_ap(void);
	char is_all_set(void);
	QString get_current_channels(void);
	char get_status();
	unsigned char can_start(void);
	
};


#endif // QT_SNIF_H
