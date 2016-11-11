#ifndef PKCS11VERSION_H
#define PKCS11VERSION_H

#define QUALIPKCS11_VERSAO_MAIOR               2
#define QUALIPKCS11_VERSAO_DEPENDENCIAS        1
#define QUALIPKCS11_VERSAO_MENOR               6
#define QUALIPKCS11_VERSAO_LANCAMENTO          0
#define QUALIPKCS11_VERSAO_STR                 "2.1.7-0"

#if DEBUG
#define QUALIPKCS11_FILEFLAGS                  VS_FF_DEBUG
#else
#define QUALIPKCS11_FILEFLAGS                  0
#endif

#define QUALIPKCS11_COMMENTS                   " "
#define QUALIPKCS11_COMPANYNAME                "QualiConsult LTDA"
#define QUALIPKCS11_FILEDESCRIPTION            "Implementacao da PKCS11 para cartoes QualiConsult"
#define QUALIPKCS11_FILEVERSION                QUALIPKCS11_VERSAO_STR
#define QUALIPKCS11_INTERNALNAME               "qualipkcs11.dll"
#define QUALIPKCS11_LEGALCOPYRIGHT             "Copyright QualiConsult, todos os direitos reservados"
#define QUALIPKCS11_ORIGINALFILENAME           "qualipkcs11.dll"
#define QUALIPKCS11_PRODUCTNAME                "SIGNext PKCS#11"
#define QUALIPKCS11_PRODUCTVERSION             QUALIPKCS11_VERSAO_STR

#endif

