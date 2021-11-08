#include "cidparser.h"
#include "qstring.h"

qstr get_card_mfr_id(uint8_t mid)
{
    switch (mid)
    {
        case 0x02:
            return "Sandisk_New"; //what?
        case 0x11:
            return"Toshiba";
        case 0x13:
            return "Micron";
        case 0x15:
            return "Samsung";
        case 0x45:
            return "Sandisk";
        case 0x70:
            return "Kingston";
        case 0x74:
            return "Transcend";
        case 0x88:
            return "Foresee";
        case 0x90:
            return "SkHynix";
        case 0x8f:
            return "UNIC";
        case 0xf4:
            return "Biwin";
        case 0xfe:
            return "Micron"; //mmm?
        default:
            return "Unknown";
    }
}

qstr get_card_type(uint8_t type)
{
    switch (type)
    {
        case 0x00:
            return "RemovableDevice";
        case 0x01:
            return "BGA (Discrete embedded)";
        case 0x02:
            return "POP";
        case 0x03:
            return "RSVD";
        default:
            return"Unknown";
    }
}

bool CIDParser::PraseCID(qbyte raw_cid, mmcCARD::CIDInfo &cid_info, bool ufs_id)
{
    if (ufs_id)
    {
        if (raw_cid.startsWith("KM"))
        {
            cid_info.Manufacturer = "Samsung";
            cid_info.ManufacturerId = "0x1CE"; //wmanufacturerid
        }
        else if (raw_cid.startsWith("H9"))
        {
            cid_info.Manufacturer = "SkHynix";
            cid_info.ManufacturerId = "0x1AD";
        }
        else if (raw_cid.startsWith("MT"))
        {
            cid_info.Manufacturer = "Micron";
            cid_info.ManufacturerId = "0x12C";
        }
        else if (raw_cid.startsWith("Z"))
        {
            cid_info.Manufacturer = "Micron";
            cid_info.ManufacturerId = "0x02C";
        }
        else if (raw_cid.startsWith("TH"))
        {
            cid_info.Manufacturer = "TOSHIBA";
            cid_info.ManufacturerId = "0x198";
        }

        cid_info.ProductName = raw_cid.data();
        cid_info.OEMApplicationId = get_hex(raw_cid.toHex().mid(0, 4).toUShort(0, 0x10));//0000;
        cid_info.CardBGA = "eUFS";
    }
    else
    {
        mmcCARD::emmc_card_info_cid_t m_cid = {};
        memset(&m_cid, 0x00, sizeof(m_cid));
        memcpy(&m_cid, raw_cid.data(), sizeof(m_cid));

        cid_info = {};
        struct {
            char pnm[6]{0x00};
        } _pnm = {};
        memcpy(&_pnm.pnm[0], &m_cid.pnm0, sizeof(_pnm.pnm[0]));
        memcpy(&_pnm.pnm[1], &m_cid.pnm1, sizeof(_pnm.pnm[1]));
        memcpy(&_pnm.pnm[2], &m_cid.pnm2, sizeof(_pnm.pnm[2]));
        memcpy(&_pnm.pnm[3], &m_cid.pnm3, sizeof(_pnm.pnm[3]));
        memcpy(&_pnm.pnm[4], &m_cid.pnm4, sizeof(_pnm.pnm[4]));
        memcpy(&_pnm.pnm[5], &m_cid.pnm5, sizeof(_pnm.pnm[5]));
        QByteArray pnm((char*)&_pnm, sizeof(_pnm));

        struct {
            char psn[4]{0x00};
        } _psn = {};
        memcpy(&_psn.psn[0], &m_cid.psn0, sizeof(_psn.psn[0]));
        memcpy(&_psn.psn[1], &m_cid.psn1, sizeof(_psn.psn[1]));
        memcpy(&_psn.psn[2], &m_cid.psn2, sizeof(_psn.psn[2]));
        memcpy(&_psn.psn[3], &m_cid.psn3, sizeof(_psn.psn[3]));
        QByteArray psn((char*)&_psn, sizeof(_psn));

        QString prv_min(QString().sprintf("%d", (uint8_t)(m_cid.pdrv >> 4)));
        QString prv_maj(QString().sprintf("%d", (uint8_t)(m_cid.pdrv & 0xf)));
        QString mdt_month(QString().sprintf("%d", (uint8_t)(m_cid.mdt >> 4)));
        QString mdt_year(QString().sprintf("%d", (uint16_t)(m_cid.mdt & 0xf) + 2013)); //todo

        cid_info.ManufacturerId = get_hex(m_cid.mid);
        cid_info.Manufacturer = get_card_mfr_id(m_cid.mid);
        cid_info.CardBGA = get_card_type(m_cid.cbx);
        cid_info.OEMApplicationId = get_hex(m_cid.oid);
        cid_info.ProductName = QString("%0").arg(pnm.trimmed().data());
        cid_info.ProductRevision = QString(prv_min + "." + prv_maj);
        cid_info.ProductSerialNumber = QString("0x%0").arg(psn.toHex().data());
        cid_info.ManufacturingDate = QString(mdt_month + "/" + mdt_year);
    }

    return 1;
}
