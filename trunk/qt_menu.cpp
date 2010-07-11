#include <QtGui>
#include <QMenu>
#include <QMenuBar>
#include <QFileDialog>
#include "qt_menu.h"
#include "qt_common.h"
#include "common.h"
#include "sniffer.h"
#include "qt_table.h"
 


MyMenu::MyMenu(MySniff *sniff, MyTable *mtable)
{
	this->sniff=sniff;
	this->mtable=mtable;
	createActions();
	createMenus();	
	this->new_capture();
//	start_menu->setDisabled(TRUE);
//	mstart_stop->setDisabled(TRUE);
}


void MyMenu::createMenus()
{
	
		file_menu = menuBar()->addMenu("&File");
		file_menu->addAction(mfile_new);
		file_menu->addAction(mfile_open);
		file_menu->addAction(mfile_quit);
		//file_menu->addAction(mfile_open);
		//file_menu->addAction(mfile_save);
	
		start_menu = menuBar()->addMenu("&Start");
		start_menu->addAction(mstart_start);
		start_menu->addAction(mstart_stop);
		
		set_menu = menuBar()->addMenu("&Set");
		set_menu->addAction(mset_interface);
		set_menu->addAction(mset_channels);
		//fileMenu->addAction(openAct);
		//fileMenu->addAction(saveAct);
		//fileMenu->addAction(printAct);
		//fileMenu->addSeparator();
		//fileMenu->addAction(exitAct);
		
		
		
		
		crack_menu = menuBar()->addMenu("&Crack");
		crack_menu->addAction(mcrack_load_dict);
		crack_menu->addAction(mcrack_set_target);
		crack_menu->addAction(mcrack_start);
	//	crack_menu->addAction(mcrack_stop);
		
		
}



void MyMenu::createActions()
{
	mstart_start = new QAction(tr("&Start"), this);
//	start_start->setShortcuts(QKeySequence(tr("Ctrl+S")));
	mstart_start->setStatusTip(tr("Start a new capture"));
	connect(mstart_start, SIGNAL(triggered()), this, SLOT(start_capture()));
	
	mstart_stop = new QAction(tr("&Stop"), this);
//	start_stop->setShortcuts(tr("Ctrl+D"));
	mstart_stop->setStatusTip(tr("Stop capturing"));
	connect(mstart_stop, SIGNAL(triggered()), this, SLOT(stop_capture()));


	mset_interface = new QAction(tr("&Interface"), this);
//	start_stop->setShortcuts(tr("Ctrl+D"));
	mset_interface->setStatusTip(tr("Set interface to capture"));
	connect(mset_interface, SIGNAL(triggered()), this, SLOT(set_capture_interface()));	
	
	mset_channels = new QAction(tr("&Channels"), this);
//	start_stop->setShortcuts(tr("Ctrl+D"));
	mset_channels->setStatusTip(tr("Set channels to capture"));
	connect(mset_channels, SIGNAL(triggered()), this, SLOT(set_capture_channels()));	

	mfile_new = new QAction(tr("&New"), this);
//	start_stop->setShortcuts(tr("Ctrl+D"));
	mfile_new->setStatusTip(tr("Start a new capture"));
	connect(mfile_new, SIGNAL(triggered()), this, SLOT(new_capture()));	
	
	mfile_open = new QAction(tr("&Open"), this);
//	start_stop->setShortcuts(tr("Ctrl+D"));
	mfile_open->setStatusTip(tr("Open a file"));
	connect(mfile_open, SIGNAL(triggered()), this, SLOT(open_capture_file()));	
	
	
	mfile_quit = new QAction(tr("&Quit"), this);
//	start_stop->setShortcuts(tr("Ctrl+D"));
	mfile_quit->setStatusTip(tr("Exit program"));
	connect(mfile_quit, SIGNAL(triggered()), this, SLOT(quit()));	


	//crack
	mcrack_load_dict = new QAction(tr("&Load dictionary"), this);
//	start_stop->setShortcuts(tr("Ctrl+D"));
	mcrack_load_dict->setStatusTip(tr("Loads a file that has a wordlist"));
	connect(mcrack_load_dict, SIGNAL(triggered()), this, SLOT(load_dictionary()));	


	mcrack_set_target = new QAction(tr("&Set target"), this);
//	start_stop->setShortcuts(tr("Ctrl+D"));
	mcrack_set_target->setStatusTip(tr("You must capture at least first two messages form a handshake"));
	connect(mcrack_set_target, SIGNAL(triggered()), this, SLOT(set_target()));	
	
	//mcrack_start

	mcrack_start = new QAction(tr("&Start"), this);
//	start_stop->setShortcuts(tr("Ctrl+D"));
	mcrack_start->setStatusTip(tr("Try find the password"));
	connect(mcrack_start, SIGNAL(triggered()), this, SLOT(start_crack()));	

/*	
	mcrack_stop = new QAction(tr("&Stop"), this);
//	start_stop->setShortcuts(tr("Ctrl+D"));
	mcrack_stop->setStatusTip(tr("Stop finding the password"));
	connect(mcrack_stop, SIGNAL(triggered()), this, SLOT(stop_crack()));	
*/			
				
	
}







char MyMenu::start_capture()
{
	
	if (sniff->start()!=0){
		xlog_err(LEVEL2,this,"Alert","Can't start capture");
		return -1;
	}
	
	set_menu->setDisabled(TRUE);
	mstart_start->setDisabled(TRUE);
	mstart_stop->setDisabled(FALSE);
	
	return 0;
	
}

char MyMenu::stop_capture()
{
	//
	if (sniff->stop()==0){
		set_menu->setDisabled(FALSE);
		mstart_start->setDisabled(FALSE);
		mstart_stop->setDisabled(TRUE);
		return 0;
	}else{
		xlog_err(LEVEL2,this,"Alert","Can't stop capture");
		return -1;
	}
	
}


//void thread_stop(){
	
//}





void MyMenu::new_capture()
{
	
	sniff->try_stop();
	sniff->clear_ap();
	
	mtable->clear_all();
	
	if (sniff->can_start() == 0){
		start_menu->setDisabled(TRUE);
	}else{
		start_menu->setDisabled(FALSE);
	}
	mstart_start->setDisabled(FALSE);
	mstart_stop->setDisabled(TRUE);
	set_menu->setDisabled(FALSE);
}

void MyMenu::at_exit()
{
	log_err(LEVEL10,(char *)"WILL quit");
	sniff->try_stop();
	sniff->clear_all();
	
	mtable->clear_all();
	
}

void MyMenu::quit(){
	QApplication::quit();
}


void MyMenu::set_capture_interface()
{
//! [2]
	
	pcap_if_t *alldevsp,*listall;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	
	//if (status == TH_STARTED){
	//	xlog_err(LEVEL9,this,"INFO","First you must stop capture")
	//}
	
	//errbuf[0]='\0';
	
	
	if (pcap_findalldevs(&alldevsp,errbuf)!=0){
		
		xlog_err(LEVEL2,this,"Alert","Can't get interfaces: %s",errbuf);
		
		return ;
	}
		
	
    QStringList items;
    
	if (alldevsp==NULL){
		xlog_err(LEVEL2,this,"Alert","Can't find devices. Check your permissions!");
		//pcap_freealldevs(alldevsp);
		return ;
	}
	
	//
	listall=alldevsp;
	while (listall!=NULL){
		items << tr(listall->name);
		listall=listall->next;
	}
	
	pcap_freealldevs(alldevsp);
	
	
	
    bool ok;
    QString item = QInputDialog::getItem(this, tr("Wireless interface"),
                                         tr("Wireless interface:"), items, 0, false, &ok);
    if (ok && !item.isEmpty()){
		if (sniff->cfg_interface(item.toLatin1().data())==0){
			start_menu->setDisabled(FALSE);
			mstart_start->setDisabled(FALSE);
			mstart_stop->setDisabled(TRUE);
		}
	}

}

void MyMenu::open_capture_file()
{
	QString fileName; 
	fileName = QFileDialog::getOpenFileName(this,
		tr("Open PCAP file"), "", "PCAP file (*.cap);;Any file (*)");
	if (fileName!=NULL){
		if (sniff->cfg_read_fname(fileName.toLatin1().data())==0){
			
			start_menu->setDisabled(TRUE);
			mstart_start->setDisabled(FALSE);
			mstart_stop->setDisabled(TRUE);
			set_menu->setDisabled(TRUE);
			
			sniff->start_offline();
			//mstart_start->setDisabled(FALSE);
			//mstart_stop->setDisabled(TRUE);
		}else{
			xlog_err(LEVEL2,this,"Alert","Can't open filename");
		}
	}
}


void MyMenu::load_dictionary()
{
	QString fileName; 
	fileName = QFileDialog::getOpenFileName(this,
		tr("Load dictionary"), "", "Any file (*)");
	if (fileName!=NULL){
		if (sniff->crack->set_filename(fileName.toLatin1().data())==0){
			//start_menu->setDisabled(TRUE);
			//sniff->start_offline();
			//sniff->
			//mstart_start->setDisabled(FALSE);
			//mstart_stop->setDisabled(TRUE);
			
		}else{
			xlog_err(LEVEL2,this,"Alert","Can't load dictionary");
		}
	}
}


void MyMenu::start_crack()
{
	sniff->crack->start();
}



void MyMenu::stop_crack()
{
	sniff->crack->stop();
}


void MyMenu::set_capture_channels()
{
	
	bool ok;


	QString text = QInputDialog::getText(this, "Channels",
										 "Channels:", QLineEdit::Normal,
										 sniff->get_current_channels(), &ok);
	
	if (ok && !text.isEmpty()){
		//textLabel->setText(text);
		sniff->cfg_chann(text.toLatin1().data());
	}
	
}

void MyMenu::set_target()
{
	
	QStringList items;
    bool ok;
	const struct access_point *aps;
	
	
	aps = get_fap();
	
	
	while (aps!=NULL){
		if (is_part_handshake(aps)==1)
			items << QString::number(aps->id +1);
		aps = aps->next;
	
	}
	
	if (items.isEmpty() == false){		
		QString item = QInputDialog::getItem(this, tr("Ap to crack"),
											 tr("Select ap:"), items, 0, false, &ok);
		
		aps = get_iap(item.toUInt()-1);
		
		if (aps == NULL){
			xlog_err(LEVEL5,this,"Alert","Can't have a null ap here in set target");
			return ;
		}else{
			sniff->crack->set_ap(aps);
		}
		
	}else{
		xlog_err(LEVEL10,this,"Alert","Can't find any ap with eapol messages");
	}
}



