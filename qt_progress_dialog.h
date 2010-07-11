#ifndef QT_PROGRESS_DIALOG_H
#define QT_PROGRESS_DIALOG_H

#include <QWidget>
#include <QProgressDialog>
#include <unistd.h>


//! DON'T USE IT!!!!!
//! NEEDS A LOT OF MODIFICATIONS

class MyProgress : QWidget
{
			Q_OBJECT
			
signals:
	void percent_changed(int);
		
//public slots:			
private:
		QProgressDialog *progress_bar;
		off_t total_val; //of pkgs to read
		off_t total_crt_val;
		char crt_percent;
			
public: 
	MyProgress(QWidget *parent,off_t total);
	void update_percent(off_t new_val);
	void progress_finish();
	//~MyProgress();
	
};


#endif // QT_PROGRESS_DIALOG_H
