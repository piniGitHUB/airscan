#ifndef QT_CRACK_H
#define QT_CRACK_H


#include <pthread.h>
#include <QWidget>
#include "sniffer.h"

#define CRACK_AP_SET 0x01
#define CRACK_FILE_SET 0x02
#define CRACK_ON 0x04


class MyCrack{
	pthread_t th_start_crack;
	char *filename;
	const struct access_point *ap;
	char status;
	QWidget *parent;
	
public:
	MyCrack(QWidget *parent, char *filename=NULL,const struct access_point *ap=NULL);	
	char start();
	char stop();
	char set_filename(char *filename);
	char set_ap(const struct access_point *ap);
	void thread_quit();
	//char stop();
	
	
};


#endif // QT_CRACK_H
