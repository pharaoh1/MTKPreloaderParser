#ifndef PRELOADER_PARSER_H
#define PRELOADER_PARSER_H

#include <structures.h>

class QIODevice;

class EMIParser
{
public:
    EMIParser(QIODevice *preloader);
    ~EMIParser();

    bool PrasePreloader();

private:
   QIODevice *m_preloader{0x00};
};

#endif // PRELOADER_PARSER_H
