#ifndef QT_TH_IFACE_H
#define QT_TH_IFACE_H

#include <QWidget>
#include <QObject>

class MyThreadInterface : QWidget
{
	
	Q_OBJECT

private:
	QWidget *parent;
	
public:
	MyThreadInterface(QWidget *parent);
	void emit_message(char *msg);
	
public slots:
	void print_message(char *msg);
	
signals:
	void message_recieved(char *msg);
	
};	
#endif // QT_TH_IFACE_H
