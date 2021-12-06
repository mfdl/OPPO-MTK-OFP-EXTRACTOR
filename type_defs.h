#ifndef M_DEFS_H
#define M_DEFS_H

#include "QtCore"
#include <windows.h>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <conio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define qnull_hnd ((HANDLE) (LONG_PTR)-1)
#ifdef __cplusplus
}
#endif

#define qMinLen(X, Y) \
    __extension__ ({ __typeof__(X) _X = (X); __typeof__(Y) _Y = (Y); _X < _Y ? _X : _Y; })

#define QNATIVE_PATH qdir::toNativeSeparators

using namespace std;

#define qnull nullptr
#define qzero 0
#define qthrow throwException

#define _SHARED_PTR QSharedPointer
#define _SMART_PTR std::unique_ptr

extern unsigned long long download_max;

typedef unsigned __LONG32 qdword;
typedef ULARGE_INTEGER qlarge_int;
typedef WORD qatom;

typedef QObject qobj;
typedef void qvoid;
typedef bool qbool;
typedef int qint;
typedef unsigned int quint;
typedef unsigned long long qlong;
typedef signed char qschar;
typedef unsigned char qchar;
typedef unsigned short qshort;

typedef quint64_be qlong_be;
typedef quint64_le qlong_le;
typedef quint32_le quint_le;
typedef quint32_be quint_be;
typedef quint16_be qshort_be;
typedef quint16_le qshort_le;

typedef QBuffer qbuff;
typedef QIODevice qiodev;
typedef QLatin1String ql1char;
typedef QElapsedTimer qtimer;
typedef QByteArray qbyte;
typedef QString qstr;
typedef QStringList qstrl;
typedef QFile qfile;
typedef QFileInfo qfileinfo;
typedef QDir qdir;

typedef QVector<qchar> qvec_u8;
typedef QVector<qshort> qvec_u16;
typedef QVector<quint> qvec_uu2;
typedef QVector<qlong> qvec_u64;
typedef QVector<qstrl> qvec_strl;
typedef QVector<qstr> qvec_str;
typedef QVector<QUuid> qvec_guid;

typedef QMultiMap<qshort, qshort> qwordmap;

#endif // M_DEFS_H
