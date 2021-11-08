#include "preloader_parser.h"
#include "cidparser.h"

bool EMIParser::PrasePreloader(QIODevice &emi_dev)
{
    if (!emi_dev.seek(0x00))
        return 0;

    mtkPreloader::gfh_info_t gfh_info = {};
    if (!emi_dev.read((char*)&gfh_info, sizeof(gfh_info)))
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
    if (gfh_info.magic == 0x434d4d45
            || gfh_info.magic == 0x5f534655) //!MTK_BOOT_REGION!
    {
        qsizetype seek_off = (gfh_info.magic == 0x5f534655)?0x1000: 0x800; //UFS_LUN & EMMC_BOOT
        if (!emi_dev.seek(seek_off))
            return 0;

        memset(&gfh_info, 0x00, sizeof(gfh_info));
        if (!emi_dev.read((char*)&gfh_info, sizeof(gfh_info)))
            return 0;

        if (gfh_info.length == 0
                || gfh_info.magic != 0x14d4d4d) //!MTK_PRELOADER_MAGIC!
        {
            qInfo().noquote() << qstr("invalid/unsupported mtk_boot_region data{%0}").arg(get_hex(gfh_info.magic));
            return 0;
        }

        if (!emi_dev.seek(0x00))
            return 0;

        emi_idx = emi_dev.readAll().indexOf(MTK_BLOADER_INFO_BEGIN);
        if (emi_idx == -1)
        {
            qInfo().noquote() << qstr("invalid/unsupported mtk_boot_region data{%0}").arg(get_hex(gfh_info.magic));
            return 0;
        }

        if (!emi_dev.seek(0x00))
            return 0;
    }

    qbyte BldrInfo = {};
    qstr platform = {"MT6752"};
    qstr flash_dev = get_pl_flash_dev(gfh_info.flash_dev);

    if (gfh_info.magic == 0x5f4b544d) //!MTK_BLOADER_INFO!
    {
        BldrInfo.resize(emi_dev.size());

        if (!emi_dev.seek(0x00))
            return 0;
        if (!emi_dev.read(BldrInfo.data(), BldrInfo.size()))
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

        if (!emi_dev.seek(0x00))
            return 0;

        qbyte prl_info = emi_dev.readAll();
        platform = get_emi_platform(prl_info);

        if (!emi_dev.seek(0x00))
            return 0;

        quint emilength = 0x1000; //!MAX_EMI_LEN
        quint emi_loc = gfh_info.length - gfh_info.sig_length - sizeof(quint);

        if (emi_idx == 0x00)
        {
            if (!emi_dev.seek(emi_loc))
                return 0;

            if (!emi_dev.read((char*)&emilength, sizeof(quint)))
                return 0;

            if (emilength == 0)
            {
                qInfo().noquote() << qstr("invalid/unsupported mtk_bloader_info data{%0}").arg(get_hex(emi_loc));
                return 0;
            }

            emi_idx = emi_loc - emilength;
        }

        BldrInfo.resize(emilength);
        if (!emi_dev.seek(emi_idx))
            return 0;
        if (!emi_dev.read(BldrInfo.data(), BldrInfo.size()))
            return 0;
    }

    struct BLoaderInfo_VXX_TAG
    {
        char m_identifier[0x1b]{0x00};
        char m_filename[0x3d]{0x00};
        quint32 m_version{0x00}; //V116
        quint32 m_chksum_seed{0x00}; //22884433
        quint32 m_start_addr{0x00}; //90007000
        char m_bin_identifier[8]{0x00}; //MTK_BIN
        quint32 m_num_emi_settings{0x00}; //!# number of emi settings.
    } bldr = {};
    memcpy(&bldr, BldrInfo.data(), sizeof(bldr));
    qbyte emi_hdr((char*)bldr.m_identifier , sizeof(bldr.m_identifier ));
    qbyte project_id((char*)bldr.m_filename, sizeof(bldr.m_filename));

    qInfo().noquote() << qstr("EMIInfo{%0}:%1:%2:%3:num_records[%4]").arg(emi_hdr.data(),
                                                                          platform,
                                                                          flash_dev,
                                                                          project_id,
                                                                          get_hex(bldr.m_num_emi_settings));

    if (!emi_hdr.startsWith(MTK_BLOADER_INFO_BEGIN))
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
    for (uint i = 0; i < bldr.m_num_emi_settings; i++)
    {
        mtkPreloader::MTKEMIInfo emi = {};

        if (emi_ver == 0x08)
        {
            memcpy(&emi.emi_cfg.emi_v08, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v08.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v08.emi_len);
            if (!emi.emi_cfg.emi_v08.emi_cfg.m_type)
                continue;

            qbyte dev_id = qbyte((char*)emi.emi_cfg.emi_v08.emi_cfg.m_emmc_id, sizeof(emi.emi_cfg.emi_v08.emi_cfg.m_emmc_id));

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v08.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v08.emi_cfg.m_dram_rank_size[0] +
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

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v10.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v10.emi_cfg.m_dram_rank_size[0] +
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

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v11.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v11.emi_cfg.m_dram_rank_size[0] +
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

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v12.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v12.emi_cfg.m_dram_rank_size[0] +
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

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v13.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v13.emi_cfg.m_dram_rank_size[0] +
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

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v14_emmc.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v14_emmc.emi_cfg.m_dram_rank_size[0] +
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

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v15.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v15.emi_cfg.m_dram_rank_size[0] +
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

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v16.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v16.emi_cfg.m_dram_rank_size[0] +
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

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v17.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v17.emi_cfg.m_dram_rank_size[0] +
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

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v18.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v18.emi_cfg.m_dram_rank_size[0] +
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

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v19.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v19.emi_cfg.m_dram_rank_size[0] +
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

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v20.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v20.emi_cfg.m_dram_rank_size[0] +
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

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v21.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v21.emi_cfg.m_dram_rank_size[0] +
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

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v22.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v22.emi_cfg.m_dram_rank_size[0] +
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

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v23.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v23.emi_cfg.m_dram_rank_size[0] +
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

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v24.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v24.emi_cfg.m_dram_rank_size[0] +
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

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v25.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v25.emi_cfg.m_dram_rank_size[0] +
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

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v27.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v27.emi_cfg.m_dram_rank_size[0] +
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

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v28.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v28.emi_cfg.m_dram_rank_size[0] +
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

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v30.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v30.emi_cfg.m_dram_rank_size[0] +
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

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v31.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v31.emi_cfg.m_dram_rank_size[0] +
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

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v32.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v32.emi_cfg.m_dram_rank_size[0] +
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

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v35.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v35.emi_cfg.m_dram_rank_size[0] +
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

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v36.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v36.emi_cfg.m_dram_rank_size[0] +
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

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v38.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v38.emi_cfg.m_dram_rank_size[0] +
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

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid, is_ufs);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v39.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v39.emi_cfg.m_dram_rank_size[0] +
                    emi.emi_cfg.emi_v39.emi_cfg.m_dram_rank_size[1] +
                    emi.emi_cfg.emi_v39.emi_cfg.m_dram_rank_size[2] +
                    emi.emi_cfg.emi_v39.emi_cfg.m_dram_rank_size[3]);
        }
        else if(emi_ver == 0x31 || emi_ver == 0x34 || emi_ver == 0x36) //MTK_BLOADER_INFO_v49 - MTK_BLOADER_INFO_v52 - MTK_BLOADER_INFO_v54
        {
            memcpy(&emi.emi_cfg.emi_v49, BldrInfo.mid(idx).data(), sizeof(emi.emi_cfg.emi_v49.emi_cfg));
            idx += sizeof(emi.emi_cfg.emi_v49.emi_len);
            if (!emi.emi_cfg.emi_v49.emi_cfg.m_type)
                continue;

            bool is_ufs(emi.emi_cfg.emi_v49.emi_cfg.m_id_length != 0x9);//len = 0x9 = eMMC & 0xe, 0xf = eUFS
            qbyte dev_id = qbyte((char*)&emi.emi_cfg.emi_v49.emi_cfg.m_ufs_id, sizeof(emi.emi_cfg.emi_v49.emi_cfg.m_ufs_id));
            dev_id.resize(emi.emi_cfg.emi_v49.emi_cfg.m_id_length);

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid, is_ufs);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v49.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v49.emi_cfg.m_dram_rank_size[0] +
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

            mmcCARD::CIDInfo m_cid = {};
            CIDParser::PraseCID(dev_id, m_cid, is_ufs);

            emi.index = i;
            emi.flash_id = dev_id.toHex().data();
            emi.manufacturer_id = m_cid.ManufacturerId;
            emi.manufacturer = m_cid.Manufacturer;
            emi.ProductName = m_cid.ProductName;
            emi.OEMApplicationId = m_cid.OEMApplicationId;
            emi.CardBGA = m_cid.CardBGA;
            emi.dram_type = get_dram_type(emi.emi_cfg.emi_v51.emi_cfg.m_type);
            emi.dram_size = get_unit(emi.emi_cfg.emi_v51.emi_cfg.m_dram_rank_size[0] +
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

//int32_t RelocateExtBootloader(uint32_t srcAddr, uint32_t srcLen, uint32_t searchAddr, uint32_t *pExtBootloaderLen)
//{
//   MTK_BL_ROMInfo_v1_ST *pBlRomInfo = NULL;

//   kal_uint32 extblLoadAddr = INVALID_START_ADDR;
//   kal_uint32 extblLoadLen  = 0;

//   kal_uint32 *p = (kal_uint32*)searchAddr;
//   kal_uint32 *pSearchEnd = (kal_uint32*)(srcAddr + srcLen - sizeof(MTK_BL_ROMInfo_v1_ST));

//   if(srcLen < sizeof(MTK_BL_ROMInfo_v1_ST))
//   {
//      return INVALID_START_ADDR;
//   }

//   //Rewind for the partial read
//   if(p  >= (kal_uint32*)(srcAddr + sizeof(MTK_BL_ROMInfo_v1_ST)))
//   {
//      p -= sizeof(MTK_BL_ROMInfo_v1_ST)/4;
//   }
//   else
//   {
//      p = (kal_uint32*)srcAddr;
//   }

//   for(; p<=pSearchEnd; p++)
//   {
//      if(memcmp(p, "MTK_BOOT_LOADER_ROMINFO_V01", sizeof("MTK_BOOT_LOADER_ROMINFO_V01")) == 0)
//      {
//         kal_uint32 calcChecksum = Calc_Chksum((kal_uint32)p, PATTERN_ID_LEN);
//         MTK_BL_ROMInfo_v1_ST *pBlRomInfo = (MTK_BL_ROMInfo_v1_ST*)p;

//         BL_PRINT(LOG_DEBUG, "Addr=%x, calc=%d, val=%d\n\r", p, calcChecksum, pBlRomInfo->m_bl_header.m_super_id_chksum);
//         BL_PRINT(LOG_DEBUG, "length=%d, addr=%x\n\r", pBlRomInfo->m_bl_length, pBlRomInfo->m_bl_load_address);

//         if(calcChecksum == pBlRomInfo->m_bl_header.m_super_id_chksum)
//         {
//            extblLoadAddr = pBlRomInfo->m_bl_load_address;
//            extblLoadLen  = pBlRomInfo->m_bl_length + sizeof(MTK_BL_ROMInfo_Tail_v1_ST);
//            break;
//         }
//      }
//   }

//   if(extblLoadAddr != INVALID_START_ADDR)
//   {
//      if(extblLoadAddr != srcAddr)
//      {
//         kal_uint32 copyLen = extblLoadLen<srcLen ? extblLoadLen : srcLen;

//         /* Make sure the load address is in bank 0 */
//         if(extblLoadAddr >= 0x10000000 && extblLoadAddr+copyLen > 0x10000000)
//         {
//            BL_PRINT(LOG_ERROR, "Invalad load addr %x\n\r", extblLoadAddr);
//            return INVALID_START_ADDR;
//         }

//         memmove((void*)extblLoadAddr, (void*)srcAddr, copyLen);
//      }

//      if(pExtBootloaderLen)
//      {
//         *pExtBootloaderLen = extblLoadLen;
//      }
//   }

//   return extblLoadAddr;
//}
