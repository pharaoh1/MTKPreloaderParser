#include "preloader_parser.h"
#include "qdebug.h"
#include "cidparser.h"
#include "qfile.h"

EMIParser::EMIParser(QIODevice *preloader)
    : m_preloader(preloader)
{}

EMIParser::~EMIParser()
{
    if (this->m_preloader)
    {
        this->m_preloader->close();
        this->m_preloader = Q_NULLPTR;
    }
}

qstr get_hex(qlonglong num)
{
    return qstr("0x%0").arg(qstr().setNum(num , 0x10).toLower());
}

qstr getUnit(quint64 bytes)
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

qstr get_pl_sig_type(uint8_t sig_type)
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

qstr get_pl_flash_dev(uint8_t flash_dev)
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

qstr get_dram_type(quint16 type)
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
        case  0x104:
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
        default:
            return "Unknown";
    }
}

qstr get_emi_platform(qbyte emi_buf)
{
    qstr emi_dev = {};
    qbyte serach0("AND_ROMINFO_v");
    qsizetype idx0 = emi_buf.indexOf(serach0);
    if (idx0 != -1)
    {
        emi_dev = emi_buf.mid(idx0 + 20, 6);
        if (emi_dev == "MT6752")
        {
            qbyte serach1("bootable/bootloader/preloader/platform/mt");
            qsizetype idx1 = emi_buf.indexOf(serach1);
            if (idx1 != -1)
            {
                emi_dev = emi_buf.mid(idx1 + serach1.length() - 2, 6);
            }

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
    }
    return emi_dev.toUpper();
}

bool EMIParser::PrasePreloader()
{
    if (!this->m_preloader->seek(0x00))
        return 0;

    mtkPreloader::gfh_info_t gfh_info = {};
    if (!this->m_preloader->read((char*)&gfh_info, sizeof(gfh_info)))
        return 0;

    if (gfh_info.length == 0
            || (gfh_info.magic != 0x14d4d4d //!PRELOADER
                && gfh_info.magic != 0x5f4b544d //!MTK_BLOADER_INFO
                && gfh_info.magic != 0x434d4d45 //!EMMC_BOOT0
                && gfh_info.magic != 0x5f534655)) //!UFS_LUN0
    {
        qInfo().noquote() << qstr("invalid/unsupported mtk_boot_region file format{%0}").arg(get_hex(gfh_info.magic));
        return 0;
    }

    qint64 emi_idx = 0x00;
    qbyte pattern("MTK_BLOADER_INFO_v");
    if (gfh_info.magic == 0x434d4d45
            || gfh_info.magic == 0x5f534655) //!MTK_BOOT_REGION!
    {
        qsizetype seek_off = (gfh_info.magic == 0x5f534655)?0x1000: 0x800; //UFS_LUN & EMMC_BOOT
        if (!this->m_preloader->seek(seek_off))
            return 0;

        memset(&gfh_info, 0x00, sizeof(gfh_info));
        if (!this->m_preloader->read((char*)&gfh_info, sizeof(gfh_info)))
            return 0;

        if (gfh_info.length == 0
                || gfh_info.magic != 0x14d4d4d) //!MTK_PRELOADER_MAGIC!
        {
            qInfo().noquote() << qstr("invalid/unsupported mtk_boot_region data{%0}").arg(get_hex(gfh_info.magic));
            return 0;
        }

        if (!this->m_preloader->seek(0x00))
            return 0;

        emi_idx = this->m_preloader->readAll().indexOf(pattern);
        if (emi_idx == -1)
        {
            qInfo().noquote() << qstr("invalid/unsupported mtk_boot_region data{%0}").arg(get_hex(gfh_info.magic));
            return 0;
        }

        if (!this->m_preloader->seek(0x00))
            return 0;
    }

    qbyte BldrInfo = {};
    qstr platform = {"MT6752"};
    qstr flash_dev = get_pl_flash_dev(gfh_info.flash_dev);

    if (gfh_info.magic == 0x5f4b544d) //!MTK_BLOADER_INFO!
    {
        BldrInfo.resize(this->m_preloader->size());

        if (!this->m_preloader->seek(0x00))
            return 0;
        if (!this->m_preloader->read(BldrInfo.data(), BldrInfo.size()))
            return 0;
    }
    else
    {
        if (gfh_info.length == 0
                || gfh_info.magic != 0x14d4d4d) //!MTK_PRELOADER_MAGIC!
        {
            qInfo().noquote() << qstr("invalid/unsupported mtk_boot_region data{%0}").arg(get_hex(gfh_info.magic));
            return 0;
        }

        if (!this->m_preloader->seek(0x00))
            return 0;

        qbyte prl_info = this->m_preloader->readAll();
        platform = get_emi_platform(prl_info);

        if (!this->m_preloader->seek(0x00))
            return 0;

        quint emilength = 0x1000; //!MAX_EMI_LEN
        quint emi_loc = gfh_info.length - gfh_info.sig_length - sizeof(quint);

        if (emi_idx == 0x00)
        {
            if (!this->m_preloader->seek(emi_loc))
                return 0;

            if (!this->m_preloader->read((char*)&emilength, sizeof(quint)))
                return 0;

            if (emilength == 0)
            {
                qInfo().noquote() << qstr("invalid/unsupported mtk_bloader_info data{%0}").arg(get_hex(emi_loc));
                return 0;
                return 0;
            }

            emi_idx = emi_loc - emilength;
        }

        BldrInfo.resize(emilength);
        if (!this->m_preloader->seek(emi_idx))
            return 0;
        if (!this->m_preloader->read(BldrInfo.data(), BldrInfo.size()))
            return 0;
    }

    struct MTKBloaderInfo
    {
        char hdr[0x1b]{0x00};
        char pre_bin[0x3d]{0x00};
        quint32 reserved0{0x00};
        quint32 reserved1{0x00};
        quint32 reserved2{0x00};
        char mtk_bin[0x8]{0x00};
        quint32 total_emis{0x00};
    } bldr = {};
    memcpy(&bldr, BldrInfo.data(), sizeof(bldr));
    qbyte emi_hdr((char*)bldr.hdr, sizeof(bldr.hdr));
    qbyte project_id((char*)bldr.pre_bin, sizeof(bldr.pre_bin));

    qInfo().noquote() << qstr("EMIInfo{%0}:%1:%2:%3:num_records[%4]").arg(emi_hdr.data(),
                                                                                 platform,
                                                                                 flash_dev,
                                                                                 project_id,
                                                                                 get_hex(bldr.total_emis));

    if (!emi_hdr.startsWith(pattern))
    {
        qInfo().noquote() << qstr("invalid/unsupported mtk_emi_info{%0}").arg(emi_hdr.data());
        return 0;
    }

    QFile BLDRINFO(emi_hdr);
    BLDRINFO.open(QIODevice::WriteOnly);
    BLDRINFO.write(BldrInfo);

    emi_hdr.remove(0, 0x12);
    quint8 emi_ver = emi_hdr.toInt(nullptr, 0xa);

    qInfo(".....................................................");

    qsizetype idx = sizeof(bldr);
    for (uint i = 0; i < bldr.total_emis; i++)
    {
        mtkPreloader::MTKEMIInfo emi = {};

        if (emi_ver == 0x08)
        {
            memcpy(&emi.emi_cfg.emi_v08, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v08.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v08.emi_len);
            if (!emi.emi_cfg.emi_v08.emi_cfg.m_type)
                continue;


            qbyte dev_id = qbyte((char*)emi.emi_cfg.emi_v08.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v08.emi_cfg.m_emmc_id));

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            cid.PraseCID(m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v08.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v08.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v08.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v08.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v08.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0xa)
        {
            memcpy(&emi.emi_cfg.emi_v10, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v10.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v10.emi_len);
            if (!emi.emi_cfg.emi_v10.emi_cfg.m_type)
                continue;


            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v10.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v10.emi_cfg.m_emmc_id));
            dev_id.resize(emi.emi_cfg.emi_v10.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            cid.PraseCID(m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v10.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v10.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v10.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v10.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v10.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0xb)
        {
            memcpy(&emi.emi_cfg.emi_v11, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v11.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v11.emi_len);
            if (!emi.emi_cfg.emi_v11.emi_cfg.m_type)
                continue;


            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v11.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v11.emi_cfg.m_emmc_id));
            dev_id.resize(emi.emi_cfg.emi_v11.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            cid.PraseCID(m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v11.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v11.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v11.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v11.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v11.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0xc)
        {
            memcpy(&emi.emi_cfg.emi_v12, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v12.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v12.emi_len);
            if (!emi.emi_cfg.emi_v12.emi_cfg.m_type)
                continue;


            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v12.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v12.emi_cfg.m_emmc_id));
            dev_id.resize(emi.emi_cfg.emi_v12.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            cid.PraseCID(m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v12.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v12.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v12.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v12.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v12.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0xd)
        {
            memcpy(&emi.emi_cfg.emi_v13, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v13.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v13.emi_len);
            if (!emi.emi_cfg.emi_v13.emi_cfg.m_type)
                continue;


            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v13.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v13.emi_cfg.m_emmc_id));
            dev_id.resize(emi.emi_cfg.emi_v13.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            cid.PraseCID(m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v13.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v13.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v13.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v13.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v13.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0xe) //combo => (TODO) for NAND type. //gfh_info.flash_dev != 0x5
        {
            memcpy(&emi.emi_cfg.emi_v14_emmc, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v14_emmc.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v14_emmc.emi_len);
            if (!emi.emi_cfg.emi_v14_emmc.emi_cfg.m_type)
                continue;


            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v14_emmc.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v14_emmc.emi_cfg.m_emmc_id));
            //dev_id.resize(emi.emi_cfg.emi_v14_emmc.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            cid.PraseCID(m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v14_emmc.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v14_emmc.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v14_emmc.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v14_emmc.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v14_emmc.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0xf) //FIX_ME . wired flash id's =>4B 47 FD 77 00 00 00 11 03 84 04 00 B1 53 00 00
        {
            memcpy(&emi.emi_cfg.emi_v15, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v15.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v15.emi_len);
            if (!emi.emi_cfg.emi_v15.emi_cfg.m_type)
                continue;


            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v15.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v15.emi_cfg.m_emmc_id));
            //dev_id.resize(emi.emi_cfg.emi_v15.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            cid.PraseCID(m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v15.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v15.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v15.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v15.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v15.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0x10)
        {
            memcpy(&emi.emi_cfg.emi_v16, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v16.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v16.emi_len);
            if (!emi.emi_cfg.emi_v16.emi_cfg.m_type)
                continue;


            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v16.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v16.emi_cfg.m_emmc_id));
            dev_id.resize(emi.emi_cfg.emi_v16.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            cid.PraseCID(m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v16.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v16.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v16.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v16.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v16.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0x11)
        {
            memcpy(&emi.emi_cfg.emi_v17, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v17.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v17.emi_len);
            if (!emi.emi_cfg.emi_v17.emi_cfg.m_type)
                continue;


            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v17.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v17.emi_cfg.m_emmc_id));
            dev_id.resize(emi.emi_cfg.emi_v17.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            cid.PraseCID(m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v17.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v17.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v17.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v17.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v17.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0x12)
        {
            memcpy(&emi.emi_cfg.emi_v18, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v18.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v18.emi_len);
            if (!emi.emi_cfg.emi_v18.emi_cfg.m_type)
                continue;


            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v18.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v18.emi_cfg.m_emmc_id));
            dev_id.resize(emi.emi_cfg.emi_v18.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            cid.PraseCID(m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v18.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v18.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v18.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v18.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v18.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0x13)
        {
            memcpy(&emi.emi_cfg.emi_v19, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v19.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v19.emi_len);
            if (!emi.emi_cfg.emi_v19.emi_cfg.m_type)
                continue;


            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v19.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v19.emi_cfg.m_emmc_id));
            dev_id.resize(emi.emi_cfg.emi_v19.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            cid.PraseCID(m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v19.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v19.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v19.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v19.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v19.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0x14)
        {
            memcpy(&emi.emi_cfg.emi_v20, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v20.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v20.emi_len);
            if (!emi.emi_cfg.emi_v20.emi_cfg.m_type)
                continue;


            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v20.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v20.emi_cfg.m_emmc_id));
            dev_id.resize(emi.emi_cfg.emi_v20.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            cid.PraseCID(m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v20.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v20.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v20.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v20.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v20.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0x15)
        {
            memcpy(&emi.emi_cfg.emi_v21, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v21.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v21.emi_len);
            if (!emi.emi_cfg.emi_v21.emi_cfg.m_type)
                continue;


            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v21.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v21.emi_cfg.m_emmc_id));
            dev_id.resize(emi.emi_cfg.emi_v21.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            cid.PraseCID(m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v21.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v21.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v21.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v21.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v21.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0x16)
        {
            memcpy(&emi.emi_cfg.emi_v22, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v22.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v22.emi_len);
            if (!emi.emi_cfg.emi_v22.emi_cfg.m_type)
                continue;


            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v22.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v22.emi_cfg.m_emmc_id));
            dev_id.resize(emi.emi_cfg.emi_v22.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            cid.PraseCID(m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v22.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v22.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v22.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v22.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v22.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0x17)
        {
            memcpy(&emi.emi_cfg.emi_v23, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v23.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v23.emi_len);
            if (!emi.emi_cfg.emi_v23.emi_cfg.m_type)
                continue;


            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v23.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v23.emi_cfg.m_emmc_id));
            dev_id.resize(emi.emi_cfg.emi_v23.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            cid.PraseCID(m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v23.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v23.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v23.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v23.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v23.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0x18)
        {
            memcpy(&emi.emi_cfg.emi_v24, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v24.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v24.emi_len);
            if (!emi.emi_cfg.emi_v24.emi_cfg.m_type)
                continue;


            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v24.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v24.emi_cfg.m_emmc_id));
            dev_id.resize(emi.emi_cfg.emi_v24.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            cid.PraseCID(m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v24.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v24.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v24.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v24.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v24.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0x19)
        {
            memcpy(&emi.emi_cfg.emi_v25, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v25.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v25.emi_len);
            if (!emi.emi_cfg.emi_v25.emi_cfg.m_type)
                continue;


            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v25.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v25.emi_cfg.m_emmc_id));
            dev_id.resize(emi.emi_cfg.emi_v25.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            cid.PraseCID(m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v25.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v25.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v25.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v25.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v25.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0x1b)
        {
            memcpy(&emi.emi_cfg.emi_v27, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v27.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v27.emi_len);
            if (!emi.emi_cfg.emi_v27.emi_cfg.m_type)
                continue;


            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v27.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v27.emi_cfg.m_emmc_id));
            dev_id.resize(emi.emi_cfg.emi_v27.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            cid.PraseCID(m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v27.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v27.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v27.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v27.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v27.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0x1c)
        {
            memcpy(&emi.emi_cfg.emi_v28, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v28.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v28.emi_len);
            if (!emi.emi_cfg.emi_v28.emi_cfg.m_type)
                continue;


            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v28.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v28.emi_cfg.m_emmc_id));
            //dev_id.resize(emi.emi_cfg.emi_v28.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            cid.PraseCID(m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v28.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v28.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v28.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v28.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v28.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0x1e)
        {
            memcpy(&emi.emi_cfg.emi_v30, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v30.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v30.emi_len);
            if (!emi.emi_cfg.emi_v30.emi_cfg.m_type)
                continue;

            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v30.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v30.emi_cfg.m_emmc_id));
            dev_id.resize(emi.emi_cfg.emi_v30.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            cid.PraseCID(m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v30.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v30.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v30.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v30.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v30.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0x1f)
        {
            memcpy(&emi.emi_cfg.emi_v31, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v31.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v31.emi_len);
            if (!emi.emi_cfg.emi_v31.emi_cfg.m_type)
                continue;

            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v31.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v31.emi_cfg.m_emmc_id));
            dev_id.resize(emi.emi_cfg.emi_v31.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            cid.PraseCID(m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v31.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v31.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v31.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v31.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v31.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0x20)
        {
            memcpy(&emi.emi_cfg.emi_v32, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v32.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v32.emi_len);
            if (!emi.emi_cfg.emi_v32.emi_cfg.m_type)
                continue;

            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v32.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v32.emi_cfg.m_emmc_id));
            dev_id.resize(emi.emi_cfg.emi_v32.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            cid.PraseCID(m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v32.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v32.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v32.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v32.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v32.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0x23)
        {
            memcpy(&emi.emi_cfg.emi_v35, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v35.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v35.emi_len);
            if (!emi.emi_cfg.emi_v35.emi_cfg.m_type)
                continue;

            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v35.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v35.emi_cfg.m_emmc_id));
            dev_id.resize(emi.emi_cfg.emi_v35.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            cid.PraseCID(m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v35.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v35.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v35.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v35.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v35.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0x24)
        {
            memcpy(&emi.emi_cfg.emi_v36, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v36.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v36.emi_len);
            if (!emi.emi_cfg.emi_v36.emi_cfg.m_type)
                continue;

            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v36.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v36.emi_cfg.m_emmc_id));
            dev_id.resize(emi.emi_cfg.emi_v36.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            cid.PraseCID(m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v36.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v36.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v36.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v36.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v36.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0x26)
        {
            memcpy(&emi.emi_cfg.emi_v38, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v38.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v38.emi_len);
            if (!emi.emi_cfg.emi_v38.emi_cfg.m_type)
                continue;

            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v38.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v38.emi_cfg.m_emmc_id));
            dev_id.resize(emi.emi_cfg.emi_v38.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            cid.PraseCID(m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v38.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v38.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v38.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v38.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v38.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0x27
                || emi_ver == 0x28
                || emi_ver == 0x2d
                || emi_ver == 0x2f) //MTK_BLOADER_INFO_v39 => MTK EMI V2 combo mode. !common.
        {
            memcpy(&emi.emi_cfg.emi_v39, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v39.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v39.emi_len);
            if (!emi.emi_cfg.emi_v39.emi_cfg.m_type)
                continue;

            bool is_ufs(emi.emi_cfg.emi_v39.emi_cfg.m_id_length != 0x9);//len = 0x9 = eMMC & 0xe, 0xf = eUFS

            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v39.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v39.emi_cfg.m_emmc_id));
            dev_id.resize(emi.emi_cfg.emi_v39.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            if (!is_ufs) //eMMC
            {
                cid.PraseCID(m_cid);
            }
            else
            {
                if (dev_id.startsWith("KM"))
                {
                    m_cid.Manufacturer = "Samsung";
                    m_cid.ManufacturerId = "0x1CE"; //wmanufacturerid
                }
                else if (dev_id.startsWith("H9"))
                {
                    m_cid.Manufacturer = "SkHynix";
                    m_cid.ManufacturerId = "0x1AD";
                }
                else if (dev_id.startsWith("MT"))
                {
                    m_cid.Manufacturer = "Micron";
                    m_cid.ManufacturerId = "0x12C";
                }
                else if (dev_id.startsWith("Z"))
                {
                    m_cid.Manufacturer = "Micron";
                    m_cid.ManufacturerId = "0x02C";
                }
                else if (dev_id.startsWith("TH"))
                {
                    m_cid.Manufacturer = "TOSHIBA";
                    m_cid.ManufacturerId = "0x198";
                }

                m_cid.ProductName = dev_id.data();
                m_cid.OEMApplicationId = get_hex(dev_id.toHex().mid(0, 4).toUShort(0, 0x10)).toStdString();//0000;
                m_cid.CardBGA = "eUFS";
            }

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v39.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v39.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v39.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v39.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v39.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0x31 || emi_ver == 0x34) //MTK_BLOADER_INFO_v49 - MTK_BLOADER_INFO_v52
        {
            memcpy(&emi.emi_cfg.emi_v49, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v49.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v49.emi_len);
            if (!emi.emi_cfg.emi_v49.emi_cfg.m_type)
                continue;

            bool is_ufs(emi.emi_cfg.emi_v49.emi_cfg.m_id_length != 0x9);//len = 0x9 = eMMC & 0xe, 0xf = eUFS
            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v49.emi_cfg.m_ufs_id, sizeof(emi.emi_cfg.emi_v49.emi_cfg.m_ufs_id));
            dev_id.resize(emi.emi_cfg.emi_v49.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            if (!is_ufs) //eMMC
            {
                cid.PraseCID(m_cid);
            }
            else
            {
                if (dev_id.startsWith("KM"))
                {
                    m_cid.Manufacturer = "Samsung";
                    m_cid.ManufacturerId = "0x1CE"; //wmanufacturerid
                }
                else if (dev_id.startsWith("H9"))
                {
                    m_cid.Manufacturer = "SkHynix";
                    m_cid.ManufacturerId = "0x1AD";
                }
                else if (dev_id.startsWith("MT"))
                {
                    m_cid.Manufacturer = "Micron";
                    m_cid.ManufacturerId = "0x12C";
                }
                else if (dev_id.startsWith("Z"))
                {
                    m_cid.Manufacturer = "Micron";
                    m_cid.ManufacturerId = "0x02C";
                }
                else if (dev_id.startsWith("TH"))
                {
                    m_cid.Manufacturer = "TOSHIBA";
                    m_cid.ManufacturerId = "0x198";
                }

                m_cid.ProductName = dev_id.data();
                m_cid.OEMApplicationId = get_hex(dev_id.toHex().mid(0, 4).toUShort(0, 0x10)).toStdString();//0000;
                m_cid.CardBGA = "eUFS";
            }

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v49.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v49.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v49.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v49.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v49.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0x33) //MTK_BLOADER_INFO_v51
        {
            memcpy(&emi.emi_cfg.emi_v51, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v51.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v51.emi_len);
            if (!emi.emi_cfg.emi_v51.emi_cfg.m_type)
                continue;

            bool is_ufs(emi.emi_cfg.emi_v51.emi_cfg.m_id_length != 0x9);//len = 0x9 = eMMC & 0xe, 0xf = eUFS
            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v51.emi_cfg.m_ufs_id, sizeof(emi.emi_cfg.emi_v51.emi_cfg.m_ufs_id));
            dev_id.resize(emi.emi_cfg.emi_v51.emi_cfg.m_id_length);

            CIDParser cid(dev_id.toStdString());
            mmcCARD::CIDInfo m_cid = {};
            if (!is_ufs) //eMMC
            {
                cid.PraseCID(m_cid);
            }
            else
            {
                if (dev_id.startsWith("KM"))
                {
                    m_cid.Manufacturer = "Samsung";
                    m_cid.ManufacturerId = "0x1CE"; //wmanufacturerid
                }
                else if (dev_id.startsWith("H9"))
                {
                    m_cid.Manufacturer = "SkHynix";
                    m_cid.ManufacturerId = "0x1AD";
                }
                else if (dev_id.startsWith("MT"))
                {
                    m_cid.Manufacturer = "Micron";
                    m_cid.ManufacturerId = "0x12C";
                }
                else if (dev_id.startsWith("Z"))
                {
                    m_cid.Manufacturer = "Micron";
                    m_cid.ManufacturerId = "0x02C";
                }
                else if (dev_id.startsWith("TH"))
                {
                    m_cid.Manufacturer = "TOSHIBA";
                    m_cid.ManufacturerId = "0x198";
                }

                m_cid.ProductName = dev_id.data();
                m_cid.OEMApplicationId = get_hex(dev_id.toHex().mid(0, 4).toUShort(0, 0x10)).toStdString();//0000;
                m_cid.CardBGA = "eUFS";
            }

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId.c_str();
            emi.manufacturer = m_cid.Manufacturer.c_str();
            emi.ProductName = m_cid.ProductName.c_str();
            emi.OEMApplicationId = m_cid.OEMApplicationId.c_str();
            emi.CardBGA = m_cid.CardBGA.c_str();
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v51.emi_cfg.m_type);
            emi.dram_size = getUnit(emi.emi_cfg.emi_v51.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v51.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v51.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v51.emi_cfg.m_dram_rank_size[3]);
        }
        else
        {
            qInfo().noquote() << qstr("EMI version not supported{%0}").arg(get_hex(emi_ver));
            return 0;
        }

        if (!emi.flash_id.size())
            continue;

        qInfo().noquote() << qstr("EMIInfo{%0}:%1:%2:%3:%4:%5:%6:DRAM:%7:%8").arg(get_hex(emi.index),
                                                                                     emi.flash_id,
                                                                                     emi.manufacturer_id,
                                                                                     emi.manufacturer,
                                                                                     emi.ProductName,
                                                                                     emi.OEMApplicationId,
                                                                                     emi.CardBGA,
                                                                                     emi.dram_type,
                                                                                     emi.dram_size);
    }

    return 0;
}

