#include <qt_progress_dialog.h>


//! DON'T USE IT!!!!!
//! NEEDS A LOT OF MODIFICATIONS


MyProgress::MyProgress(QWidget *parent,off_t total){

	//progress_bar = new QProgressDialog(parent);
	progress_bar = new QProgressDialog("test","cancel",0,100,parent);
	//	progress_bar->autoClose();
	
	//progress_bar->setMaximum(100);
	//progress_bar->setMinimum(0);
	connect(this,SIGNAL(percent_changed(int)),progress_bar,SLOT(setValue(int)));
	//connect(progress_bar,SIGNAL(canceled()),this,SLOT(stop()));
	//connect(progress_bar,SIGNAL(finished(int)),this,SLOT(stop()));
	//void percent_changed(int);
	//progress_bar->show();

	this->progress_bar = NULL;
total_val=total; //of pkgs to read
total_crt_val=0;
crt_percent=0;



	
	
}


void MyProgress::progress_finish()
{
	//this->progress_bar->done(0);
//	static int x=0;
///	log_err(LEVEL1,"x=%d",x);
	//x++;
	if (this->progress_bar==NULL)
		return ;
	disconnect(this,SIGNAL(percent_changed(int)),progress_bar,SLOT(setValue(int)));
	
	//this->progress_bar->setValue(100);
	//this->progress_bar
//	this->progress_bar->destroy();
	this->progress_bar->accept();
	delete(this->progress_bar);
	this->progress_bar=NULL;
//	this->stop();
	//delete(this->progress_bar)
}

void MyProgress::update_percent(off_t new_val)
{
	int per;

	total_crt_val+=new_val;
	
	per = (float)(((float)total_crt_val/this->total_val))*100;
	
	//xlog_err(LEVEL10,parent,"Alert","per:%04x new_val:%04x total:%04x crt:%04x",per,new_val,total_val,total_crt_val);
	//log_err(LEVEL2,"per:%d new_val:%d total:%d crt:%d x:%f",per,new_val,total_val,total_crt_val,x);
	//per=80;
	//for (int i=0;i<1000;i++)
		//for (int j=0;j<100;j++){
			//int x;
			//x=1;
		//}
	
	
	if (per != this->crt_percent){
		emit this->percent_changed(per);
	}
}
