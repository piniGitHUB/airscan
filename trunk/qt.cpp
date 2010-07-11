#include <QtGui>
#include <QMainWindow>
#include <QWidget>

#include <QApplication>
#include <QAbstractItemView>
#include <QVBoxLayout>
#include <QThread>
#include <QLabel>
#include <QAction>

//#include <qtconcurrentrun.h>
//#include <unistd.h>

#include "qt_interface.h"
#include "qt_menu.h"

#include "common.h"
#include "sniffer.h"
#include "qt_dialog.h"
#include "qt_table.h"

#include "qt_th_iface.h"
#include "qt.h"





/*xBug 
  1. if interface is changed we must verify new channels
  2. i don't know if when table is cleared items are realy distroyed 
  3. never free 	cr=new struct th_crack; in MyCrack::start
  
*/


//global variable

MyTable  *tableq=NULL;

MyThreadInterface *threadq = NULL;

//int percent;

/*

void xlog_err(int debug_level, QWidget * parent,char *title,char *fmt, ...)
{
	debug_level=debug_level;

	char buf[LOGBUFFER_SIZE] = {'\0'};
	va_list msg;
	va_start(msg,fmt);
	vsnprintf(buf, sizeof(buf), fmt, msg);
	va_end(msg);
	buf[sizeof(buf) - 1] = '\0';
	
	QMessageBox::StandardButton reply;
	reply = QMessageBox::information(parent, title, buf);

}
*/

void xlog_err(int debug_level, QWidget * parent,QString title,QString fmt, ...)
{
debug_level=debug_level;
	char buf[LOGBUFFER_SIZE] = {'\0'};
	va_list msg;
	va_start(msg,fmt);
	vsnprintf(buf, sizeof(buf), fmt.toLatin1().data(), msg);
	va_end(msg);
	buf[sizeof(buf) - 1] = '\0';
	
	QMessageBox::StandardButton reply;
	reply = QMessageBox::information(parent, title, buf);

}



void qt_update_fields(struct access_point *ap)
{
	
	if (tableq==NULL){
		qWarning("You are using qt_update_fields without initialising table!!!!");
		return ;
	}
	if (ap==NULL){
		qWarning("Display NULL AP!");
		return ;
	}
	

	
	if (tableq->maxRow()<=ap->id){
		tableq->addRow(ap);
	}else{
		tableq->updateRow(ap);
	}
}



//use it in offline mode
void qt_insert_all(struct access_point *fap)
{
	struct access_point *tmp_ap;
			
	
	if (tableq==NULL){
		qWarning("You are using qt_update_fields without initialising table!!!!");
		return ;
	}
	if (fap==NULL){
		qWarning("Display NULL AP!");
		return ;
	}
	
	tmp_ap=fap;
	
	while (tmp_ap!=NULL){
		
		if (tableq->maxRow()<=tmp_ap->id){
			tableq->addRow(tmp_ap);
		}else{
			//should never be here
			tableq->updateRow(tmp_ap);	
		}
		
		tmp_ap=tmp_ap->next;
		
	}
	
//	BUG !!! NU VA PUTEA NICIODATA AFISA MESAJELE DE EROARE DE AICI
	//sniffq->stop();

	

	//!!!! TO MODIFY!!!!!!!!!!!!!!!!!!!!
/////////!!!!!!!!!!!!!!!!!!!!!!!!!!!
//	sniffq->progress_finish();
	
}


void qt_exit_unexpected(char* err,struct access_point *fap)
{
	//if (err == NULL)
		//xlog_err(LEVEL1,windowq,"Alert!","Loop died unexpected!");
	//else
		//xlog_err(LEVEL1,windowq,"Alert!","Loop died unexpected :%s",err);
	
	if (is_offline() == 1){
		if (fap!=NULL){
			qt_insert_all(fap);
		}
	}

}

void qt_update_progress_bar(off_t value)
{
//	value=value;
//	if (sniffq  == NULL){
//		log_err(LEVEL1,(char *)"Sniffer is not initialised");
//		return ;
//	}
	
	//sniffq->update_progress_bar_percent(value);
	
	
}

void x_message(char *msg)
{
	threadq->emit_message(msg);
}

void crack_finish(int x)
{
	
}


int qt_main(int argc, char *argv[])
{
	//int argc=0;
	//char argv[1][1];
	//argv[0][0]='\0';
	//if ()
	//fork();
	QApplication app(argc,argv);

	QWidget window;
	
	MySniff *sniff;
	
	QWidget *menuq;
	QLabel *infoLabel;
	
	
	window.resize(MAIN_WINDOW_X,MAIN_WINDOW_Y);

	threadq = new MyThreadInterface(&window);
		
	//create table with access points
	tableq= new MyTable(&window);
	
	sniff=new MySniff(&window);	
	
	
	
	
	
	
	
	
	//create menus
	menuq= new MyMenu(sniff,tableq);
	menuq->setMaximumHeight(20);	
	
	//create a label with informations
    infoLabel = new QLabel("<i></i>");
    infoLabel->setFrameStyle(QFrame::StyledPanel | QFrame::Sunken);
    infoLabel->setAlignment(Qt::AlignCenter);
	
	app.connect(&app,SIGNAL(aboutToQuit()),menuq,SLOT(at_exit()));
	
	//set layout
    QVBoxLayout *layout = new QVBoxLayout;
	layout->addWidget(menuq);
    layout->addWidget(tableq);
    layout->addWidget(infoLabel);
    
	window.setLayout(layout);

	
	
	
	window.show();
	
	//table.addrow();
	
	//run(test1,&app);
	//test1(&app);
    //QFuture<int> f1 = run(test1,&app);
    //QFuture<void> f2 = run(test2,&window,&table);
	
	
	//while(1){};
	
	//window.show();
	return app.exec();
	 
	 
}

void *qt_interface(void *x)
{
	x=x;
	qt_main(NULL,NULL);
	return NULL;
}




/*
int main(int argc, char *argv[]){
		

	return qt_main(argc,argv);
}*/
/*int main(int argc, char *argv[]){
	qt_main(argc,argv);
}
*/
/*
  
    QFuture<void> f1 = run(hello, 1);
    QFuture<void> f2 = run(hello, 2);
    f1.waitForFinished();
    f2.waitForFinished();
  
  
 QTableWidget* mw=new QTableWidget(0);
 
  QStringList labels;
  labels << "Greeting" << "Planet";
  mw->setColumnCount(2);
  mw->setEditTriggers(QAbstractItemView::AllEditTriggers);
  mw->setHorizontalHeaderLabels(labels);
  mw->horizontalHeader()->setStretchLastSection(true);
  mw->insertRow(0);
  QTableWidgetItem* item=new QTableWidgetItem("Hello");
  item->setFlags(Qt::ItemIsEnabled);
  item->setWhatsThis("You can change this task's comment, start time and end time.");
  mw->setItem(0,0,item);
  QTableWidgetItem* item2=new QTableWidgetItem("World");
  mw->setItem(0,1,item2);
  mw->show();
  khello.exec();
  */


