SOURCES += sniffer.c \
    xmalloc.c \
    qt.cpp \
    main.cpp \
    qt_sniff.cpp \
    qt_menu.cpp \
    qt_table.cpp \
    qt_progress_dialog.cpp \
    qt_crack.cpp \
    qt_th_iface.cpp \
    radiotap-parser.c \
    crypt/crypto.c
LIBS += -lm \
    -lpcap \
    -lssl
HEADERS += qt_interface.h \
    qt_menu.h \
    sniffer.h \
    common.h \
    crypt/crypto.h \
    qt_dialog.h \
    qt_snif.h \
    qt_common.h \
    qt_table.h \
    qt_progress_dialog.h \
    qt_crack.h \
    qt_th_iface.h \
    qt.h
