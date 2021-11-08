#ifndef CIDPARSER_H
#define CIDPARSER_H

#include <helper.h>

class CIDParser
{
public:
    static bool PraseCID(qbyte raw_cid, mmcCARD::CIDInfo &cid_info, bool ufs_id = 0);
};

#endif // CIDPARSER_H
