#ifndef HELPER_H
#define HELPER_H

#if __GNUC__ >= 4
#define LIBEXPORT extern"C" __attribute__ ((visibility ("default")))
#else
#error  "the compiler is not supported!!"
#endif

#include <structures.h>
#include "qdebug.h"
#include "qfile.h"

static qstr get_hex(qlonglong num)
{
    return qstr("0x%0").arg(qstr().setNum(num , 0x10).toLower());
}

static qstr get_unit(quint64 bytes)
{
    // According to the Si standard KB is 1000 bytes, KiB is 1024
    // but on windows sizes are calculated by dividing by 1024 so we do what they do.
    const quint64 kb = 1024;
    const quint64 mb = 1024 * kb;
    const quint64 gb = 1024 * mb;
    const quint64 tb = 1024 * gb;
    if (bytes >= tb)
        return QLocale().toString(bytes / (double)tb, 'f', 2) + qstr::fromLatin1("TB");
    if (bytes >= gb)
        return QLocale().toString(bytes / (double)gb, 'f', 2) + qstr::fromLatin1("GB");
    if (bytes >= mb)
        return QLocale().toString(bytes / (double)mb, 'f', 2) + qstr::fromLatin1("MB");
    if (bytes >= kb)
        return QLocale().toString(bytes / (double)kb, 'f', 2) + qstr::fromLatin1("KB");

    return QLocale().toString(bytes) + qstr::fromLatin1("B");
}

static qstr get_pl_sig_type(uint8_t sig_type)
{
    switch (sig_type)
    {
        case 0x01:
            return "SIG_PHASH";
        case 0x02:
            return "SIG_SINGLE";
        case 0x03:
            return "SIG_SINGLE_AND_PHASH";
        case 0x04:
            return "SIG_MULTI";
        case 0x05:
            return "SIG_CERT_CHAIN";
        default:
            return "Unknown";
    }
}

static qstr get_pl_flash_dev(uint8_t flash_dev)
{
    switch (flash_dev)
    {
        case 0x01:
            return "NOR";
        case 0x02:
            return "NAND_SEQUENTIAL";
        case 0x03:
            return "NAND_TTBL";
        case 0x04:
            return "NAND_FDM50";
        case 0x05:
            return "EMMC_BOOT";
        case 0x06:
            return "EMMC_DATA";
        case 0x07:
            return "SF";
        case 0xc:
            return "UFS_BOOT";
        default:
            return "Unknown";
    }
}

static qstr get_dram_type(quint16 type)
{
    switch (type)
    {
        case 0x001:
            return "Discrete DDR1";
        case 0x002:
            return "Discrete LPDDR2";
        case 0x003:
            return "Discrete LPDDR3";
        case 0x004:
            return "Discrete PCDDR3";
        case 0x101:
            return "MCP(NAND+DDR1)";
        case 0x102:
            return "MCP(NAND+LPDDR2)";
        case 0x103:
            return "MCP(NAND+LPDDR3)";
        case 0x104:
            return "MCP(NAND+PCDDR3)";
        case 0x201:
            return "MCP(eMMC+DDR1)";
        case 0x202:
            return "MCP(eMMC+LPDDR2)";
        case 0x203:
            return "MCP(eMMC+LPDDR3)";
        case 0x204:
            return "MCP(eMMC+PCDDR3)";
        case 0x205:
            return "MCP(eMMC+LPDDR4)";
        case 0x206:
            return "MCP(eMMC+LPDR4X)";
        case 0x306:
            return "uMCP(eUFS+LPDDR4X)";
            //        case 0x308:
            //            return "uMCP(eUFS+LPDDR!)";
        default:
            return qstr("%0:Unknown").arg(get_hex(type));
    }
}

static qstr get_emi_platform(qbyte emi_buf)
{
    qstr emi_dev = {};
    qbyte serach0("AND_ROMINFO_v");
    qsizetype idx0 = emi_buf.indexOf(serach0);
    if (idx0 != -1)
        emi_dev = emi_buf.mid(idx0 + 20, 6);

    if (emi_dev == "MT6752")
    {
        qbyte serach1("bootable/bootloader/preloader/platform/mt");
        qsizetype idx1 = emi_buf.indexOf(serach1);
        if (idx1 != -1)
            emi_dev = emi_buf.mid(idx1 + serach1.length() - 2, 6);

        qbyte serach2("preloader_");
        qsizetype idx2 = emi_buf.indexOf(serach2);
        if (idx2 != -1)
        {
            qstr emi_dev = emi_buf.mid(idx2 + serach2.length(), sizeof(uint64_t));
            QRegExp regex0("67(\\d+)");
            if (regex0.indexIn(emi_dev)!= -1)
            {
                qsizetype dev_id = regex0.cap(1).toInt();
                emi_dev = qstr("MT67%0").arg(dev_id);
            }

            QRegExp regex1("65(\\d+)");
            if (regex1.indexIn(emi_dev)!= -1)
            {
                qsizetype dev_id = regex1.cap(1).toInt();
                emi_dev = qstr("MT65%0").arg(dev_id);
            }
        }
    }

    //    if (!emi_buf.contains(MTK_BLOADER_INFO_BEGIN))
    //    {
    //        qbyte emi_tag = emi_buf.mid(emi_buf.indexOf(MTK_BLOADER_INFO_BEGIN), 0x1b);
    //        qInfo() << "EMI_TAG" << emi_tag;
    //        if (emi_tag == "MTK_BLOADER_INFO_v04")
    //            emi_dev = "MT6516";
    //        if (emi_tag == "MTK_BLOADER_INFO_v07")
    //            emi_dev = "MT6573";
    //        if (emi_tag == "MTK_BLOADER_INFO_v08")
    //            emi_dev = "MT6575";
    //        if (emi_tag == "MTK_BLOADER_INFO_v08")
    //            emi_dev = "MT6577";
    //        if (emi_tag == "MTK_BLOADER_INFO_v10")
    //            emi_dev = "MT6589";
    //        if(emi_tag == "MTK_BLOADER_INFO_v11")
    //            emi_dev = "MT6572";
    //        if (emi_tag == "MTK_BLOADER_INFO_v12")
    //            emi_dev = "MT6582";
    //        if (emi_tag == "MTK_BLOADER_INFO_v13")
    //            emi_dev = "MT6592";
    //        if (emi_tag == "MTK_BLOADER_INFO_v00")
    //            emi_dev = "MT6595";
    //        if (emi_tag == "MTK_BLOADER_INFO_v13")
    //            emi_dev = "MT8127";
    //        if (emi_tag == "MTK_BLOADER_INFO_v10")
    //            emi_dev = "MT8135";
    //        if (emi_tag == "MTK_BLOADER_INFO_v20")
    //            emi_dev = "MT6735";
    //    }

    return emi_dev.toUpper();
}

#endif // HELPER_H
