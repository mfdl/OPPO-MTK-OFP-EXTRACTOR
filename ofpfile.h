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
    char        projName[48];
    uint64_t    unknown;
    uint32_t    reserved;
    char        cpuType[7];
    char        flashType[5];
    uint16_t    num_entries;
    char        projInfo[32];
    uint16_t    chksum;
};

struct MTKOFPMAP
{
    char        name[32];
    uint64_t    offset;
    uint64_t    length;
    uint64_t    encLength;
    char        filename[32];
    uint64_t    chksum;
};

enum ChunkTYPE : uint16_t
{
    CHUNK_TYPERAW = 0xcac1,
    CHUNK_TYPEFILL,
    CHUNK_TYPESKIP,
    CHUNK_TYPECRC
};

struct sparseHDR
{
    uint32_t    magic;
    uint16_t    major_ver {1};
    uint16_t    minor_ver {0};
    uint16_t    sparse_hdr_size {0x1c};
    uint16_t    chunk_hdr_size {0xc};
    uint32_t    block_size {0x1000};
    uint32_t    total_blocks {0};
    uint32_t    total_chunks {0};
    uint32_t    checksum {0};
};
struct chunkHDR
{
    ChunkTYPE   type {CHUNK_TYPERAW};
    uint16_t    reserved {0};
    uint32_t    chunk_size {0};
    uint32_t    total_size {0};
};

class OfpFile : public QObject
{
    Q_OBJECT

public:
    OfpFile() {}
    ~OfpFile() {}

public:
    static bool extract_partition(qstr ofp_file, qstr part_name, QIODevice &io_dev);
public:
    static bool UnpackOFPEntries(qstr ofp_file, QVector<MTKOFPMAP> &entries);
    static bool extract_partitions(qstr ofp_file, qstrl parts, qstr super_part, qstr super_io);
    static bool ConvertSparse(qstr super_part, qstr super_io);

    static void decrypt_ofp_data(qbyte input, qbyte &output, mtk_ofp_sec ofp_key);
    static bool mtk_ofp_gen_key(qbyte enc_ofp_buf, mtk_ofp_sec &ofp_key);
    static void mtk_shuffle(qbyte key, int keyLength, qbyte &data, int inputLength, bool for_key = false);
public:
    static qbool read_file(qstr path, qbyte &output, qlong offset = 0, qlong length = 0);
};

#endif // OFPFILE_H
