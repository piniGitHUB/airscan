#include <QWidget>
#include <QVBoxLayout>
//maybe we should use equivalent functions
#include <stdio.h>

#include "qt_table.h"
#include "common.h"
#include "sniffer.h"


MyTable::MyTable(QWidget *parent)
	: QWidget(parent)
{
	
	mt=new QTableWidget(this);
	
	QStringList labels;

	for (int i=0; i<QT_COLUMN_NUMBER; i++){
		switch (i){
			case QT_COLUMN_SSID:
				labels << QT_COLUMN_SSID_NAME;
				break;
			case QT_COLUMN_BSSID:
				labels << QT_COLUMN_BSSID_NAME;
				break;
			case QT_COLUMN_POWER:
				labels << QT_COLUMN_POWER_NAME;
				break;
			case QT_COLUMN_BEACON:
				labels << QT_COLUMN_BEACON_NAME;
				break;
			case QT_COLUMN_DATA:
				labels << QT_COLUMN_DATA_NAME;
				break;
			case QT_COLUMN_CONTROL:
				labels << QT_COLUMN_CONTROL_NAME;
				break;
			case QT_COLUMN_MANAGEMENT:
				labels << QT_COLUMN_MANAGEMENT_NAME;
				break;
			case QT_COLUMN_CIPHER:
				labels << QT_COLUMN_CIPHER_NAME;
				break;
			case QT_COLUMN_AUTH:
				labels << QT_COLUMN_AUTH_NAME;
			break;
			case QT_COLUMN_CHANNEL:
				labels << QT_COLUMN_CHANNEL_NAME;
				break;
			case QT_COLUMN_EAPOL:
				labels << QT_COLUMN_EAPOL_NAME;
				break;
			default:
				labels << "Unknown";
				break;
		}
	}
	

	
	column=QT_COLUMN_NUMBER;
	//mt->setRowCount(2);
	mt->setColumnCount(column);
	mt->setEditTriggers(QAbstractItemView::NoEditTriggers);
	mt->setHorizontalHeaderLabels(labels);
	

	mt->setColumnWidth(QT_COLUMN_SSID,QT_COLUMN_SSID_WIDTH);
	mt->setColumnWidth(QT_COLUMN_BSSID,QT_COLUMN_BSSID_WIDTH);
	mt->setColumnWidth(QT_COLUMN_POWER,QT_COLUMN_POWER_WIDTH);
	mt->setColumnWidth(QT_COLUMN_BEACON,QT_COLUMN_BEACON_WIDTH);
	mt->setColumnWidth(QT_COLUMN_DATA,QT_COLUMN_DATA_WIDTH);
	mt->setColumnWidth(QT_COLUMN_CONTROL,QT_COLUMN_CONTROL_WIDTH);
	mt->setColumnWidth(QT_COLUMN_MANAGEMENT,QT_COLUMN_MANAGEMENT_WIDTH);
	mt->setColumnWidth(QT_COLUMN_CIPHER,QT_COLUMN_CIPHER_WIDTH);
	mt->setColumnWidth(QT_COLUMN_AUTH,QT_COLUMN_AUTH_WIDTH);
	mt->setColumnWidth(QT_COLUMN_CHANNEL,QT_COLUMN_CHANNEL_WIDTH);
	mt->setColumnWidth(QT_COLUMN_EAPOL,QT_COLUMN_EAPOL_WIDTH);
	
	//mt->setColumnWidth(0,40);
	
	mt->setShowGrid(false);
	
	//mt->width(800);
	row=0;

	
	

	//mt->columnWidth(1);
	/*
	mt->insertRow(0);
	QTableWidgetItem *newItem = new QTableWidgetItem("Hello");
	newItem->setFlags(Qt::ItemIsEnabled);
	mt->setItem(0, 0, newItem);
	
	
	row++;
	*/
	
	QVBoxLayout *layout = new QVBoxLayout;
	layout->addWidget(mt);
//	setLayout(layout);	
	setLayout(layout);
	
}


void MyTable::clear_all()
{
	for (int i=this->row;i>=0;i--){
		mt->removeRow(i);
	}
}






QTableWidgetItem *MyTable::set_i(int mrow,int mcolumn,char *str)
{
			
	QTableWidgetItem *newItem = new QTableWidgetItem(str);
	newItem->setFlags(Qt::ItemIsEnabled);
	mt->setItem(mrow, mcolumn, newItem);
	return newItem;

}

QTableWidgetItem *MyTable::set_i(int mrow,int mcolumn,int x)
{
	char str[MAX_STR_TO_DISPLAY];
	
	snprintf(str,MAX_STR_TO_DISPLAY*sizeof(char),"%d ",x);
	
	return set_i(mrow,mcolumn,str);

}


void MyTable::addRow(struct access_point *ap)
{
	char str[MAX_STR_TO_DISPLAY];
	
	int mrow;
//	QTableWidgetItem *newItem;
	
	mrow=ap->id;
	//if (mt->rowCount()<row)
	mt->insertRow(mrow);

	
	//bssid
	snprintf(str,255*sizeof(char),(char *)"%02x:%02x:%02x:%02x:%02x:%02x ",ap->bssid[0],ap->bssid[1],ap->bssid[2],ap->bssid[3],ap->bssid[4],ap->bssid[5]);
	set_i(mrow,QT_COLUMN_BSSID,str);
	
	
	set_i(mrow,QT_COLUMN_SSID,ap->ssid);

	set_i(mrow,QT_COLUMN_POWER,ap->signal_power);
	
	set_i(mrow,QT_COLUMN_BEACON,ap->no_beacon);
	
	set_i(mrow,QT_COLUMN_DATA,ap->no_data);
	
	set_i(mrow,QT_COLUMN_CONTROL,ap->no_control);
	set_i(mrow,QT_COLUMN_MANAGEMENT,ap->no_management);
	
	str_enc(str,ap->cipher);
	set_i(mrow,QT_COLUMN_CIPHER,str);

	str_enc_auth(str,ap->auth);
	set_i(mrow,QT_COLUMN_AUTH,str);
	
	
	set_i(mrow,QT_COLUMN_CHANNEL,ap->channel);
	
	set_i(mrow,QT_COLUMN_EAPOL,is_part_handshake(ap));
	/*
	if (ap->channel>>7==0){
		set_i(mrow,QT_COLUMN_CHANNEL,ap->channel);
	}else{
		set_i(mrow,QT_COLUMN_CHANNEL,ap->channel&0x7F);
	}*/
	
	
	row++;	

	
}

void MyTable::update_i(int mrow,int mcol,char *str)
{
	QTableWidgetItem *myItem;
	QString tmp((const char *)str);
	
	myItem=mt->item(mrow,mcol);
	
	
	
	myItem->setText(tmp);
	
	
}



void MyTable::update_i(int mrow,int mcolumn,int x)
{
	char str[MAX_STR_TO_DISPLAY];
	
	snprintf(str,MAX_STR_TO_DISPLAY*sizeof(char),"%d ",x);
	
	return update_i(mrow,mcolumn,str);

}



void MyTable::updateRow(struct access_point *ap)
{
	char str[MAX_STR_TO_DISPLAY];
	int mrow;
	
	mrow=ap->id;
		
	if (mt->item(ap->id,QT_COLUMN_BSSID)==0){
		addRow(ap);
	}else{
		
		update_i(mrow,QT_COLUMN_SSID,ap->ssid);
	
		update_i(mrow,QT_COLUMN_POWER,ap->signal_power);
		
		update_i(mrow,QT_COLUMN_BEACON,ap->no_beacon);
		
		update_i(mrow,QT_COLUMN_DATA,ap->no_data);
		
		update_i(mrow,QT_COLUMN_CHANNEL,ap->channel);
		
		update_i(mrow,QT_COLUMN_CONTROL,ap->no_control);
		update_i(mrow,QT_COLUMN_MANAGEMENT,ap->no_management);
		
		update_i(mrow,QT_COLUMN_EAPOL,is_part_handshake(ap));
		
		str_enc(str,ap->cipher);
		update_i(mrow,QT_COLUMN_CIPHER,str);
		
		str_enc_auth(str,ap->auth);
		set_i(mrow,QT_COLUMN_AUTH,str);
		
	}
	
	
}


int MyTable::maxRow()
{
	return row;
}


