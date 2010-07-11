#ifndef QT_COMMON_H
#define QT_COMMON_H

#include <QWidget>


//void xlog_err(int debug_level, QWidget * parent,char *title,char *fmt, ...);
void xlog_err(int debug_level, QWidget * parent,QString title,QString fmt, ...);


#endif // QT_COMMON_H
