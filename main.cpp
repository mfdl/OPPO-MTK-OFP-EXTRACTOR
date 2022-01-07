#include <QCoreApplication>
#include <QDebug>
#include <QFile>
#include <QDir>
#include <QSpecialInteger>

#include <iostream>
#include <ofpfile.h>

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    a.isSetuidAllowed();
    a.setApplicationName("MTK OFP Extractor V1.0000.0");
    a.setApplicationVersion("1.0000.0");
    a.setOrganizationName("OPPO");
    a.setQuitLockEnabled(0);

    qInfo("..................MTK OFP Extractor.................");
    qInfo("....................................................");

    if(argc < 2)
        qInfo("Drag and drop mtk ofp file here!");

    while (1) {

        QByteArray ofp_file(0xff, Qt::Uninitialized);
        std::cin.get((char*)ofp_file.data(), 0xff);

        qInfo(".....................................................");
        qInfo().noquote() << qstr("Reading ofp file %0").arg(ofp_file.data());
        QFile ofp_dev(QDir::toNativeSeparators(ofp_file));
        if (!ofp_dev.size())
        {
            qInfo().noquote() << qstr("please input a valid file!.");
            std::cin.ignore();
        }

        qstr out_path = qfileinfo(ofp_dev).absolutePath() +"/" +
                qfileinfo(ofp_dev).fileName().replace(".ofp", qstr());
        if(!qdir(out_path).exists())
            qdir(out_path).mkdir(".");

        QVector<mtk_ofp_entry> ofp_map = {};
        if (!OfpFile::UnpackOFPEntries(ofp_file, ofp_map))
            return 0;

        qfile tmp_file = {};
        for (QVector<mtk_ofp_entry>::iterator it =
             ofp_map.begin(); it != ofp_map.end(); it++)
        {
            mtk_ofp_entry entry = *it;
            qstr pname = entry.name;
            if (pname.startsWith("super."))
                continue;

            if (pname.contains("super_map.csv"))
            {
                qfile io_dev(qstr("%0/%1").arg(out_path, pname));
                if (!io_dev.open(qiodev::ReadWrite))
                    break;

                if (!OfpFile::extract_partition(ofp_file, pname, io_dev))
                    break;
                io_dev.close();

                qbyte super_map_csv = {};
                if (!(OfpFile::read_file(io_dev.fileName(), super_map_csv)))
                    continue;

                QTextStream stream(&super_map_csv);
                while (!stream.atEnd())
                {
                    qstr line = stream.readLine();
                    if (line.contains("nv_id")) //skip header
                        continue;

                    if (line.contains(','))
                    {
                        qstrl items = line.split(',');
                        struct SuperMAP {
                            qstr nv_id;
                            qstr nv_text;
                            qstr super_0_path;
                            qstr super_1_path;
                            qstr super_2_path;
                        } sp_map = {};
                        sp_map.nv_id = items.at(0);
                        sp_map.nv_text = items.at(1);
                        sp_map.super_0_path = items.at(2);
                        sp_map.super_1_path = items.at(3);
                        sp_map.super_2_path = items.at(4);

                        qInfo().noquote() << qstr("Extracting SUPER_%0 ").arg(sp_map.nv_text);

                        qstrl nv_itesm ; nv_itesm << sp_map.super_0_path.replace(".img", "")
                                                  << sp_map.super_1_path.replace(".img", "")
                                                  << sp_map.super_2_path.replace(".img", "");

                        qstr super_tmp(qstr("%0/%1").arg(out_path, "super_tmp"));
                        qstr super_mapped(qstr("%0/%1").arg(out_path, "super_" + sp_map.nv_text + ".img"));
                        if (!OfpFile::extract_partitions(ofp_file, nv_itesm, super_tmp, super_mapped))
                            continue;
                    }
                }
            }
            else
            {
                qInfo().noquote() << qstr("Extracting %0 ").arg(pname);

                qstr save_name = pname;
                if (save_name == ("scatter"))
                    save_name = "scatter.txt";
                if(!qfileinfo(qstr("%0/%1").arg(out_path, save_name)).suffix().size())
                    save_name = save_name + QLatin1String(".img");

                tmp_file.setFileName(qstr("%0/%1").arg(out_path, save_name));
                if (!tmp_file.open(qiodev::ReadWrite))
                    continue;

                if (!OfpFile::extract_partition(ofp_file, pname, tmp_file))
                {
                    tmp_file.close();
                    continue;
                }

                tmp_file.close();

            }
        }

        ofp_file.clear();
        std::cin.ignore();
        qInfo("Drag and drop mtk ofp file here!");
    }

    return a.exec();
}
