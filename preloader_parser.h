#ifndef PRELOADER_PARSER_H
#define PRELOADER_PARSER_H

#include <structures.h>

class QIODevice;

class EMIParser
{
public:
    EMIParser(){}
    ~EMIParser(){};

    static bool PrasePreloader(QIODevice &emi_dev);
};

#endif // PRELOADER_PARSER_H
