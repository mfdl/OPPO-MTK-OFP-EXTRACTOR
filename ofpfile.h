#ifndef OFPFILE_H
#define OFPFILE_H

#include <QtCore>
#include <QObject>
#include <QCryptographicHash>
#include "inc/aes.h"
#include "inc/pem.h"
#include "inc/rsa.h"
#include "inc/err.h"
#include "inc/rsa.h"
#include "type_defs.h"

#define OFP_HDR_LEN 0x6c
#define OFP_HDR_KEY "67657969787565"
#define OFP_CONST_LEN 0x60

struct mtk_ofp_sec
{
    qbyte key = "";
    qbyte ivc = "";
};

struct mtk_ofp_hdr
{
    char     projName[48];
    qlong    unknown;
    quint    reserved;
    char     cpuType[7];
    char     flashType[5];
    qshort   num_entries;
    char     projInfo[32];
    qshort   chksum;
};

struct mtk_ofp_entry
{
    char   name[32];
    qlong  offset;
    qlong  length;
    qlong  encLength;
    char   filename[32];
    qlong  chksum;
};

enum ChunkTYPE : qshort
{
    CHUNK_TYPERAW = 0xcac1,
    CHUNK_TYPEFILL,
    CHUNK_TYPESKIP,
    CHUNK_TYPECRC
};

struct sparseHDR
{
    quint  magic;
    qshort major_ver {1};
    qshort minor_ver {0};
    qshort sparse_hdr_size {0x1c};
    qshort chunk_hdr_size {0xc};
    quint  block_size {0x1000};
    quint  total_blocks {0};
    quint  total_chunks {0};
    quint  checksum {0};
};
struct chunkHDR
{
    ChunkTYPE type {CHUNK_TYPERAW};
    qshort reserved {0};
    quint  chunk_size {0};
    quint  total_size {0};
};

class OfpFile : public QObject
{
    Q_OBJECT

public:
    OfpFile() {}
    ~OfpFile() {}

public:
    static qbool extract_partition(qstr ofp_file, qstr part_name, QIODevice &io_dev);
public:
    static qbool UnpackOFPEntries(qstr ofp_file, QVector<mtk_ofp_entry> &entries);
    static qbool extract_partitions(qstr ofp_file, qstrl parts, qstr super_part, qstr super_io);
    static qbool ConvertSparse(qstr super_part, qstr super_io);

    static qvoid decrypt_ofp_data(qbyte input, qbyte &output, mtk_ofp_sec ofp_key);
    static qbool mtk_ofp_gen_key(qbyte enc_ofp_buf, mtk_ofp_sec &ofp_key);
    static qvoid mtk_shuffle(qbyte key, qint keyLength, qbyte &data, qint inputLength, bool for_key = false);
public:
    static qbool read_file(qstr path, qbyte &output, qlong offset = 0, qlong length = 0);
};

#endif // OFPFILE_H
