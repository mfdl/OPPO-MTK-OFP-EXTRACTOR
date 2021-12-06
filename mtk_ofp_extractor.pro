QT -= gui

CONFIG += c++11 console
CONFIG -= app_bundle

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
        main.cpp \
        ofpfile.cpp

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target


#get rid of auto generated debug/release folders
CONFIG -= debug_and_release debug_and_release_target

CONFIG(debug, debug|release) {DESTDIR = tmp/debug }
CONFIG(release, debug|release) {DESTDIR = tmp/release }

OBJECTS_DIR = $$DESTDIR/.obj
MOC_DIR = $$DESTDIR/.moc
RCC_DIR = $$DESTDIR/.qrc
UI_DIR = $$DESTDIR/.u

DESTDIR = output

PRODUCT_IDENTIFIER = https://web.facebook.com/mofadal.96
PRODUCT_VERSION_NAME = 1.0.0
PRODUCT_VERSION_CODE = 1

INCLUDEPATH  += $$PWD
INCLUDEPATH  += $$PWD/openssl
INCLUDEPATH  += $$PWD/openssl/inc

LIBS += -L$$quote($$PWD/openssl/lib) \
    -llibssl \
    -llibcrypto \
    -llibeay32 \
    -llibssl32

HEADERS += \
    ofpfile.h \
    type_defs.h

RC_FILE = mtk_ofp_extractor.rc
