//qt thread interface
//prints messages trough treads

#include "qt_th_iface.h"
#include "qt_common.h"
#include "common.h"

MyThreadInterface::MyThreadInterface(QWidget *parent)
{
	this->parent = parent;
	
	connect(this,SIGNAL(message_recieved(char*)),this,SLOT(print_message(char*)));
	
}


void MyThreadInterface::print_message(char *msg)
{
	xlog_err(LEVEL10,parent,"Info",msg);
	free(msg);
	
}

void MyThreadInterface::emit_message(char *msg)
{
	emit this->message_recieved(msg);
}
