#ifndef QT_MENU_H
#define QT_MENU_H

#include <pthread.h>
#include <QMainWindow>
#include <QObject>
#include "qt_dialog.h"
#include "qt_snif.h"
#include "qt_table.h"

class MyMenu: public QMainWindow {

	Q_OBJECT
		 
private:

	MySniff *sniff;
	MyTable *mtable;
	void createActions();
	void createMenus();
		
public:
	MyMenu(MySniff *sniff, MyTable *mtable);
	
	
private slots:
	char start_capture();
	char stop_capture();
	
	void set_capture_interface();
	void set_capture_channels();
	void open_capture_file();
	void new_capture();
	void quit();
	
	void load_dictionary();
	void start_crack();
	void stop_crack();
	void set_target();
	
public slots:
	void at_exit();

	
private:
	
	QMenu *file_menu;
	QAction *mfile_new;
	QAction *mfile_open;
	QAction *mfile_quit;
	
	QMenu *start_menu;
	QAction *mstart_start;
	QAction *mstart_stop;
	
	QMenu *set_menu;
	QAction *mset_interface;
	QAction *mset_channels;
	
	QMenu *crack_menu;
	QAction *mcrack_load_dict;
	QAction *mcrack_set_target;
	QAction *mcrack_start;
	QAction *mcrack_stop;
	
};



#endif // QT_MENU_H

