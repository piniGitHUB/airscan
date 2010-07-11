#ifndef QT_INTERFACE_H
#define QT_INTERFACE_H




#ifdef __cplusplus
extern "C" {
#endif
	
void *qt_interface(void *x);
void qt_update_fields(struct access_point *ap);
void qt_insert_all(struct access_point *ap);
int qt_main(int argc, char *argv[]);
void qt_update_progress_bar(off_t value);
void qt_exit_unexpected(char* err,struct access_point *fap);
void x_message(char *msg);
void crack_finish(int x);


#ifdef __cplusplus
}
#endif


#endif // QT_INTERFACE_H
