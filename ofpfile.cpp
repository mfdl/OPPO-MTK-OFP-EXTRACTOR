#include "ofpfile.h"

void OfpFile::mtk_shuffle(qbyte key, qint keyLength, qbyte &data, qint inputLength, qbool for_key)
{
    if (for_key)
    {
        for (int i = 0; i < inputLength; i++)
        {
            qchar tmp = key.at(i%keyLength) ^ data.at(i);
            data[i] = (qchar)(((tmp & 0xf0) >> 4) | (16 * (tmp & 0xf)));
        }
    }
    else
    {
        for (int i = 0; i < inputLength; i++)
        {
            qchar k = key.at(i % keyLength);
            qchar h = ((data.at(i) & 0xf0) >> 4) | (16 * (data.at(i) & 0xf));
            data[i] = (qchar)k ^ (qchar)h;
        }
    }
}

void OfpFile::decrypt_ofp_data(qbyte input, qbyte &output, mtk_ofp_sec ofp_key)
{
    output.clear();
    AES_KEY aes_key;
    qint pos = 0;
    qchar outBuff[4096];

    AES_set_encrypt_key((const qchar*)ofp_key.key.constData(), 128, &aes_key);

    qint64 length = input.length();
    qint64 startAdd = 0;

    while (length > 0)
    {
        qsizetype read = qMinLen(0x1000, length);
        AES_cfb128_encrypt((qchar*)input.mid(startAdd, read).data(),
                           outBuff, read, &aes_key, (qchar*)ofp_key.ivc.data(), &pos, AES_DECRYPT);
        output.append((char*)outBuff, read);
        length -= read;
        startAdd += read;
    }
}

qbool OfpFile::mtk_ofp_gen_key(qbyte enc_ofp_buf, mtk_ofp_sec &ofp_key)
{
    qstr ofp_keys[9][3] = {{}};

    ofp_keys[0][0].append("67657963787565E837D226B69A495D21");
    ofp_keys[0][1].append("F6C50203515A2CE7D8C3E1F938B7E94C");
    ofp_keys[0][2].append("42F2D5399137E2B2813CD8ECDF2F4D72");

    ofp_keys[1][0].append("9E4F32639D21357D37D226B69A495D21");
    ofp_keys[1][1].append("A3D8D358E42F5A9E931DD3917D9A3218");
    ofp_keys[1][2].append("386935399137416B67416BECF22F519A");

    ofp_keys[2][0].append("892D57E92A4D8A975E3C216B7C9DE189");
    ofp_keys[2][1].append("D26DF2D9913785B145D18C7219B89F26");
    ofp_keys[2][2].append("516989E4A1BFC78B365C6BC57D944391");

    ofp_keys[3][0].append("27827963787265EF89D126B69A495A21");
    ofp_keys[3][1].append("82C50203285A2CE7D8C3E198383CE94C");
    ofp_keys[3][2].append("422DD5399181E223813CD8ECDF2E4D72");

    ofp_keys[4][0].append("3C4A618D9BF2E4279DC758CD535147C3");
    ofp_keys[4][1].append("87B13D29709AC1BF2382276C4E8DF232");
    ofp_keys[4][2].append("59B7A8E967265E9BCABE2469FE4A915E");

    ofp_keys[5][0].append("1C3288822BF824259DC852C1733127D3");
    ofp_keys[5][1].append("E7918D22799181CF2312176C9E2DF298");
    ofp_keys[5][2].append("3247F889A7B6DECBCA3E28693E4AAAFE");

    ofp_keys[6][0].append("1E4F32239D65A57D37D2266D9A775D43");
    ofp_keys[6][1].append("A332D3C3E42F5A3E931DD991729A321D");
    ofp_keys[6][2].append("3F2A35399A373377674155ECF28FD19A");

    ofp_keys[7][0].append("122D57E92A518AFF5E3C786B7C34E189");
    ofp_keys[7][1].append("DD6DF2D9543785674522717219989FB0");
    ofp_keys[7][2].append("12698965A132C76136CC88C5DD94EE91");

    ofp_keys[8][0].append("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    ofp_keys[8][1].append("ab3f76d7989207f2");
    ofp_keys[8][2].append("2bf515b3a9737835");

    qbool key_match = false;
    for(int i = 0; i < 9; ++i)
    {
        if(ofp_keys[i][0] != "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        {
            qbyte usr_obs = qbyte::fromHex(ofp_keys[i][0].toUtf8());
            qbyte usr_key = qbyte::fromHex(ofp_keys[i][1].toUtf8());
            qbyte usr_ivc = qbyte::fromHex(ofp_keys[i][2].toUtf8());

            mtk_shuffle(usr_obs, 16, usr_key, 16, true);
            mtk_shuffle(usr_obs, 16, usr_ivc, 16, true);

            ofp_key.key = QCryptographicHash::hash(usr_key, QCryptographicHash::Md5).toHex().left(16);
            ofp_key.ivc = QCryptographicHash::hash(usr_ivc, QCryptographicHash::Md5).toHex().left(16);

        }
        else
        {
            ofp_key.key = ofp_keys[i][1].toUtf8();
            ofp_key.ivc = ofp_keys[i][2].toUtf8();
        }

        qbyte dec_ofp_buf;

        decrypt_ofp_data(enc_ofp_buf, dec_ofp_buf, ofp_key);

        if(dec_ofp_buf.startsWith("MMM"))
        {
            key_match = true;
            break;
        }
    }

    if(ofp_key.key.isEmpty() || ofp_key.ivc.isEmpty())
        return false;

    return key_match;
}

qbool OfpFile::UnpackOFPEntries(qstr ofp_file, QVector<MTKOFPMAP> &entries)
{
    if(!qfileinfo(ofp_file).size())
        return 0;

    qfile io_dev(ofp_file);
    if (!io_dev.open(qiodev::ReadOnly))
        return 0;

    if (!io_dev.seek(io_dev.size() - OFP_HDR_LEN))
    {
        io_dev.close();
        return 0;
    }

    qbyte hdr_buf = io_dev.read(OFP_HDR_LEN);

    qbyte hdr_key(qbyte::fromHex(OFP_HDR_KEY));
    mtk_shuffle(hdr_key, hdr_key.length(), hdr_buf, OFP_HDR_LEN);

    mtk_ofp_hdr hdr = {};
    memcpy(&hdr, hdr_buf.data(), sizeof(hdr));
    if (hdr.num_entries == 0)
    {
        io_dev.close();
        return 0;
    }

    quint hdr_entries = hdr.num_entries * OFP_CONST_LEN;
    if (!io_dev.seek(io_dev.size() - hdr_entries - OFP_HDR_LEN))
    {
        io_dev.close();
        return 0;
    }

    qbyte entry_buf = io_dev.read(hdr_entries);
    mtk_shuffle(hdr_key, hdr_key.length(), entry_buf, hdr_entries);

    MTKOFPMAP *ofp_entry = (MTKOFPMAP*)malloc(entry_buf.length());
    memcpy(ofp_entry, entry_buf.data(), entry_buf.length());

    int entry_count = entry_buf.length() / OFP_CONST_LEN;

    if (entry_count == 0 || entry_count > 200)
    {
        io_dev.close();
        return 0;
    }

    for (int i = 0; i < entry_count; ++i)
    {
        if(!ofp_entry[i].offset || !ofp_entry[i].length)
            continue;

        MTKOFPMAP entry = {};
        memcpy(&entry, &ofp_entry[i], sizeof(ofp_entry[i]));
        entries.push_back(entry);
    }

    io_dev.close();
    return entries.count();
}


qbool OfpFile::extract_partition(qstr ofp_file, qstr part_name, qiodev &io_dev)
{
    if (!qfileinfo::exists(ofp_file))
        return 0;

    qfile ofp(ofp_file);

    mtk_ofp_hdr hdr;

    if (!ofp.isOpen())
    {
        if (!ofp.open(qiodev::ReadOnly))
            return 0;
    }

    if (!ofp.seek(0))
    {
        ofp.close();
        return 0;
    }

    mtk_ofp_sec aes_data;
    if (!mtk_ofp_gen_key(ofp.read(16), aes_data))
    {
        ofp.close();
        return 0;
    }

    if (!ofp.seek(ofp.size() - OFP_HDR_LEN))
    {
        ofp.close();
        return false;
    }

    qbyte hdr_buf = ofp.read(OFP_HDR_LEN);

    qbyte hdr_key(qbyte::fromHex(OFP_HDR_KEY));
    mtk_shuffle(hdr_key, hdr_key.length(), hdr_buf, OFP_HDR_LEN);

    memcpy(&hdr, hdr_buf.data(), sizeof(hdr));

    if (hdr.num_entries == 0)
    {
        ofp.close();
        return false;
    }

    quint hdr_entries = hdr.num_entries * OFP_CONST_LEN;

    if (!ofp.seek(ofp.size() - hdr_entries - OFP_HDR_LEN))
    {
        ofp.close();
        return false;
    }

    qbyte entry_buf = ofp.read(hdr_entries);
    mtk_shuffle(hdr_key, hdr_key.length(), entry_buf, hdr_entries);

    MTKOFPMAP *ofp_entry = (MTKOFPMAP*)malloc(entry_buf.length());
    memcpy(ofp_entry, entry_buf.data(), entry_buf.length());

    int entry_count = entry_buf.length() / OFP_CONST_LEN;

    if (entry_count == 0 || entry_count > 200)
    {
        ofp.close();
        return 0;
    }

    for (int i = 0; i < entry_count; ++i)
    {
        qstr pname = qstr("%0").arg(ofp_entry[i].name);

        if ((!ofp_entry[i].offset || !ofp_entry[i].length || !ofp_entry[i].encLength)
                || part_name != pname)
            continue;

        qlong totalRead = 0;

        ofp.seek(ofp_entry[i].offset);

        qbyte enc_data = ofp.read(ofp_entry[i].encLength);

        if((ofp_entry[i].encLength % 16) != 0)
            enc_data += 0x00 * 16 - (ofp_entry[i].encLength);

        qbyte data;
        decrypt_ofp_data(enc_data, data, aes_data);

        if (data.length() < 1)
            break;

        io_dev.write(data, ofp_entry[i].encLength);

        ofp_entry[i].length -= ofp_entry[i].encLength;
        quint64 maxLen = ofp_entry[i].length;
        while (ofp_entry[i].length > 0)
        {
            qlong size = 0x200000;
            if (ofp_entry[i].length < size)
                size = ofp_entry[i].length;

            int percntage = (int)(100.00 * ((double)totalRead / (double)maxLen));

            //            qInfo() << (qstr("Extarcting %0 {%1:%2} %3%").arg(pname,
            //                                                              qstr().setNum(totalRead, 0x10),
            //                                                              qstr().setNum(maxLen, 0x10),
            //                                                              qstr::number(percntage)));

            data = ofp.read(size);

            ofp_entry[i].length -= size;

            io_dev.write(data, data.size());

            totalRead += data.size();
        }
    }

    ofp.close();
    return true;
}

qbool OfpFile::extract_partitions(qstr ofp_file, qstrl parts, qstr super_part, qstr super_io)
{
    foreach (qstr part, parts)
    {
        qfile super_tmp(super_part);
        if (!super_tmp.open(qiodev::ReadWrite))
            break;

        if (!extract_partition(ofp_file, part, super_tmp))
            return 0;
        super_tmp.close();

        if (!ConvertSparse(super_part, super_io))
            return 0;
    }

    return 1;
}

qbool OfpFile::ConvertSparse(qstr super_part, qstr super_io)
{
    qfile in(super_part);
    qfile out(super_io);

    in.open(qfile::ReadOnly);
    out.open(qiodev::ReadWrite);

    sparseHDR sparse_header;
    chunkHDR  chunk_header;

    in.seek(0);
    out.seek(0);
    in.read((char*)&sparse_header, sizeof(sparseHDR));

    char *buff = 0;
    quint count = 0;
    qlong total = 0;
    qlong total_raw = 0;

    for (quint i = 0; i < sparse_header.total_chunks; i++)
    {
        in.read((char*)&chunk_header, sizeof(chunkHDR));

        qstr type;
        if (chunk_header.type == CHUNK_TYPERAW)
            type = "RAW";
        else if (chunk_header.type == CHUNK_TYPEFILL)
            type = "FILL";
        else if (chunk_header.type == CHUNK_TYPESKIP)
            type = "SKIP";

        qlong ssize = (qlong)chunk_header.chunk_size * sparse_header.block_size;
        total += chunk_header.chunk_size;
        total_raw += ssize;
        count++;

        switch (chunk_header.type)
        {
            case CHUNK_TYPERAW:
            {
                qlong raw_size = (qlong)chunk_header.chunk_size * sparse_header.block_size;
                while (raw_size)
                {
                    qlong write_size = std::min(raw_size, (qlong)1048576);
                    buff = (char*)calloc(write_size, sizeof(char));

                    in.read(buff, write_size);
                    out.write(buff, write_size);
                    free(buff); buff = 0;

                    raw_size -= write_size;

                    int percntage = (int)(100.00 * ((double)write_size / (double)raw_size));
                }
            } break;
            case CHUNK_TYPEFILL:
            {
                qlong fill_size = (qlong)chunk_header.chunk_size * sparse_header.block_size;
                quint fill_val = 0;

                in.read((char*)&fill_val, sizeof(quint));
                while (fill_size)
                {
                    qlong write_size = std::min(fill_size, (qlong)1048576);
                    buff = (char*)calloc(write_size, sizeof(char));

                    if (fill_val > 0)
                    {
                        const size_t s = sizeof(quint);
                        for (size_t i = 0; i < (write_size/s)*s; i+=s)
                            memcpy((char*)buff+i, &fill_val, s);
                    }

                    out.write(buff, write_size);
                    free(buff); buff = 0;

                    fill_size -= write_size;

                    int percntage = (int)(100.00 * ((double)write_size / (double)fill_size));
                }

            } break;
            case CHUNK_TYPESKIP:
            {
                qlong skip_size = (qlong)chunk_header.chunk_size * sparse_header.block_size;
                if (out.pos() + (qint64)skip_size > out.size())
                {
                    while (skip_size)
                    {
                        qlong write_size = std::min(skip_size, (qlong)1048576);
                        buff = (char*)calloc(write_size, sizeof(char));

                        out.write(buff, write_size);
                        free(buff); buff = 0;

                        skip_size -= write_size;

                        int percntage = (int)(100.00 * ((double)write_size / (double)skip_size));
                    }
                }
                else
                {
                    out.skip(skip_size);
                }
            } break;
            case CHUNK_TYPECRC:
            {

            } break;
        }
    }

    in.close();
    out.close();

    return 1;
}

qbool OfpFile::read_file(qstr path, qbyte &output, qlong offset, qlong length)
{
    path = QNATIVE_PATH(path);

    output.clear();

    if (!qfileinfo::exists(path))
        return 0;

    qfile io_dev(path);
    if (!io_dev.open(qiodev::ReadOnly))
        return 0;

    QDataStream stream = {};
    stream.setDevice(&io_dev);

    if (!io_dev.seek(offset))
    {
        io_dev.close();
        return 0;
    }

    if (length == 0)
        length = io_dev.size() - offset;

    if (offset + length > io_dev.size())
    {
        io_dev.close();
        return 0;
    }

    while (length)
    {
        qint64 read_len = qMinLen(0x100000, length);
        qbyte buff(read_len, Qt::Uninitialized);
        qint64 ret = stream.readRawData(buff.data(), read_len);
        if (ret != read_len)
        {
            buff.clear();
            io_dev.close();
            return 0;
        }

        output.append(buff);

        buff.clear();

        length -= read_len;
    }

    io_dev.close();
    return output.size();
}

