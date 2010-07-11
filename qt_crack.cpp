#include <pthread.h>
#include <errno.h>
#include "qt_crack.h"
#include "qt_interface.h"
#include "qt_common.h"
#include "sniffer.h"
#include "common.h"
#include "xmalloc.h"

MyCrack::MyCrack(QWidget *parent, char *filename,const struct access_point *ap)
{
	
	this->parent=parent;	
	this->status = 0;
	
	
	
	if (filename!=NULL)
		this->set_filename(filename);
	else
		this->filename=NULL;
	
	if (ap!=NULL)
		this->set_ap(ap);
	else
		this->ap=NULL;
	
	//this->
	
	
}

char MyCrack::set_ap(const struct access_point *ap)
{
	
	if (ap!=NULL){	
		this->ap=ap;
		this->status = this->status | CRACK_AP_SET;
		return 0;
	}else{
		this->ap=NULL;
		xlog_err(LEVEL1,parent,"Alert!","Can't set null ap");
		return -1;
	}
	
}

char MyCrack::set_filename(char *filename)
{
	
	if (filename!=NULL){	
		this->filename = (char *)xmalloc(sizeof(char)*(strlen(filename)+1));
		strcpy(this->filename,filename);
		this->status = this->status | CRACK_FILE_SET;
		return 0;
	}else{
		this->filename=NULL;
		xlog_err(LEVEL1,parent,"Alert!","Can't set null filename!?");
		return -1;
	}
	
}

char MyCrack::start()
{

	struct th_crack *cr;
	
//	if ((this->status & CRACK_ON) != 0){
//		xlog_err(LEVEL1,parent,"Alert!","Thread already started");
//		return -1;
//	}

	if ((this->status & CRACK_FILE_SET) == 0){
		xlog_err(LEVEL1,parent,"Alert!","Dictionary not loaded");
		return -1;
	}

	if ((this->status & CRACK_AP_SET) == 0){
		xlog_err(LEVEL1,parent,"Alert!","No access point to crack");
		return -1;
	}
	

	cr=new struct th_crack;
	cr->ap=this->ap;
	cr->fname=this->filename;
	
	
	if (pthread_create(&th_start_crack,NULL,crack_thread,cr) != 0){
		log_err(LEVEL1,(char *)"Can't create thread (2): %s",(char *)strerror(errno));
		xlog_err(LEVEL1,parent,"Alert","Can't create thread (2): %s",(char *)strerror(errno));
		return -1;
	}else{
		
		this->status = this->status | CRACK_ON;
	}
	
	return 0;
	
}

char MyCrack::stop()
{

	//struct th_crack *cr;
	
	if ((this->status & CRACK_ON) == 0){
		xlog_err(LEVEL1,parent,"Alert!","Thread NOT started");
		return -1;
	}
	
	
	if (pthread_cancel(th_start_crack) != 0){
		log_err(LEVEL1,(char *)"Can't create thread (2): %s",(char *)strerror(errno));
		xlog_err(LEVEL1,parent,"Alert","Can't create thread (2): %s",(char *)strerror(errno));
		return -1;
	}else{
		
		this->status = this->status & (~CRACK_ON);
	}
	
}

void MyCrack::thread_quit()
{
	this->status = this->status & (~CRACK_ON);
}

