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

        EMIParser::PrasePreloader(io_dev);
        io_dev.close();

        path.clear();
        std::cin.ignore();
        qInfo("Drag and drop the preloader/boot_region file here!");
    }

    return a.exec();
}
