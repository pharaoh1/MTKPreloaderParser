#include <QCoreApplication>
#include <QDebug>
#include <QFile>
#include <QDir>
#include <QSpecialInteger>

#include <preloader_parser.h>
#include <iostream>

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    a.isSetuidAllowed();
    a.setApplicationName("MTK Preloader Parser V4.0000.0");
    a.setApplicationVersion("4.0000.0");
    a.setOrganizationName("Mediatek");
    a.setQuitLockEnabled(0);

    qInfo("................ MTK Preloader Parser ...............");
    qInfo(".....................................................");

    if(argc < 2)
        qInfo("Drag and drop the preloader/boot_region file here0!");

    while (1) {

        QByteArray path(0xff, Qt::Uninitialized);
        std::cin.get((char*)path.data(), 0xff);

        qInfo(".....................................................");
        qInfo().noquote() << QString("Reading file %0").arg(path.data());
        QFile io_dev(QDir::toNativeSeparators(path));
        if (!io_dev.size())
        {
            qInfo().noquote() << QString("please input a valid file!.");
            std::cin.ignore();
        }

        if (!io_dev.open(QIODevice::ReadOnly))
        {
            qInfo().noquote() << QString("file open fail!(%0)").arg(qt_error_string());
            std::cin.ignore();
        }

        QVector<mtkPreloader::MTKEMIInfo> emis = {};
        EMIParser::PrasePreloader(io_dev, emis);
        io_dev.close();

        for (QVector<mtkPreloader::MTKEMIInfo>::iterator it =
             emis.begin(); it != emis.end(); it++)
        {
            mtkPreloader::MTKEMIInfo emi = *it;

            qInfo().noquote() << qstr("EMIInfo{%0}:%1:%2:%3:%4:%5:%6:DRAM:%7:%8").arg(emi.index,
                                                                                      emi.flash_id,
                                                                                      emi.manufacturer_id,
                                                                                      emi.manufacturer,
                                                                                      emi.ProductName,
                                                                                      emi.OEMApplicationId,
                                                                                      emi.CardBGA,
                                                                                      emi.dram_type,
                                                                                      emi.dram_size);
        }

        path.clear();
        std::cin.ignore();
        qInfo("Drag and drop the preloader/boot_region file here!");
    }

    return a.exec();
}
