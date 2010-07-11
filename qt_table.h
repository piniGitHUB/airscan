#ifndef QT_TABLE_H
#define QT_TABLE_H

#include <QWidget>
#include <QTableWidget>


#define QT_COLUMN_NUMBER 11


//using namespace QtConcurrent;
//don't forget to modify QT_COLUMN_NUMBER
#define QT_COLUMN_SSID 0
#define QT_COLUMN_BSSID 1
#define QT_COLUMN_POWER 2
#define QT_COLUMN_CHANNEL 3
#define QT_COLUMN_BEACON 4
#define QT_COLUMN_DATA 5
#define QT_COLUMN_CONTROL 6
#define QT_COLUMN_MANAGEMENT 7
#define QT_COLUMN_CIPHER 8
#define QT_COLUMN_AUTH 9
#define QT_COLUMN_EAPOL 10


#define QT_COLUMN_SSID_NAME "SSID"
#define QT_COLUMN_BSSID_NAME "BSSID"
#define QT_COLUMN_POWER_NAME "PWR"
#define QT_COLUMN_BEACON_NAME "Beacons"
#define QT_COLUMN_DATA_NAME "Data"
#define QT_COLUMN_CONTROL_NAME  "Cntrl"
#define QT_COLUMN_MANAGEMENT_NAME "Mngmt"
#define QT_COLUMN_CIPHER_NAME "Cipher"
#define QT_COLUMN_AUTH_NAME "AUTH"
#define QT_COLUMN_CHANNEL_NAME "Ch"
#define QT_COLUMN_EAPOL_NAME "Eapol"

#define QT_COLUMN_SSID_WIDTH 150
#define	QT_COLUMN_BSSID_WIDTH 125
#define QT_COLUMN_POWER_WIDTH 40
#define QT_COLUMN_BEACON_WIDTH 70
#define QT_COLUMN_DATA_WIDTH 40
#define QT_COLUMN_CONTROL_WIDTH 40
#define QT_COLUMN_MANAGEMENT_WIDTH 60
#define QT_COLUMN_CIPHER_WIDTH 120
#define QT_COLUMN_AUTH_WIDTH 40
#define QT_COLUMN_CHANNEL_WIDTH 40
#define QT_COLUMN_EAPOL_WIDTH 40


class MyTable : public QWidget
{
	int row;
	int column;	
	QTableWidget *mt;
	
public:
	MyTable(QWidget *parent);
	void addRow(struct access_point *ap);
	void updateRow(struct access_point *ap);
	QTableWidgetItem *set_i(int mrow,int mcolumn,int x);
	QTableWidgetItem *set_i(int mrow,int mcolumn,char *str);
	void update_i(int mrow,int mcol,char *str);
	void update_i(int mrow,int mcol,int x);
	void clear_all(void);
	int maxRow(void);
};

#endif // QT_TABLE_H
