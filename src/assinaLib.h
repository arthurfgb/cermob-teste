/* defines de unix cryptoki, direto da documentacao */
#ifndef _ASSINALIB_H
#define _ASSINALIB_H

#ifdef WIN32
#ifndef _CRT_NONSTDC_NO_DEPRECATE
#define _CRT_NONSTDC_NO_DEPRECATE
#endif
#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE
#endif
#ifndef PRIV_KEY
#define PRIV_KEY
#endif
#endif

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) \
returnType name
#define CK_DECLARE_FUNCTION(returnType, name) \
returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) \
returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR NULL
#endif

enum  status{
    SUCESS = 0000,

    ERROR_LEITURA_SLOT = 1001,
    ERROR_NF_TOKEN,
    ERROR_LOGIN,
    ERROR_PUBLICKEY,
    ERROR_NF_CKA,

    ERROR_INIT =2001 ,
    ERROR_ALLOC_BUFFER,

    ERROR_SIGN = 3001,
    ERROR_SIGN_INIT,
    ERROR_SIGN_SIZE,
    ERROR_TAMANHO_SAIDA

};
typedef enum status STATUS;

#include "pkcs11.h"
#include <stdlib.h>


//Calculates the length of a decoded string
size_t calcDecodeLength(const char* b64input) ;

//Decodes a base64 encoded string
int Base64Decode(char* b64message, unsigned char** buffer, size_t* length) ;

//Encodes a binary safe base 64 string
int Base64encode(char *encoded, const char *string, int len);

/** funcao chamada para criptografar dados
 * recebe sessao, bytes de entrada, char* para saida e se a entrada deve ser decodificada como parametros
 */
STATUS assinarBase64(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey, char* leitura, char** saida, int base64, int saida_length);

/** funcao para buscar os objetos da publickey
 * recebe sessao,
 */
CK_RV getPublicKeyObjectHandlers(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phPublicKey, CK_ULONG_PTR phPublicKeyCount);

/** funcao
*recebe sessao, a publickey
*retorna 1 se encontrou o CKA_label e 0 caso contrario
 */
int getAtributosPK(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, char* cka_label);

int searchTokenLabel(CK_SESSION_HANDLE hSession, CK_SLOT_ID_PTR pSlotList, CK_ULONG pulCount, char* tokenLabel);

CK_RV loginUser(CK_RV rv, CK_SESSION_HANDLE_PTR hSession_PTR, char* pin);


/** funcao
*Recebe:
**Token Label  (Rótulo do slot);
**PIN (Senha de login);
**CKA Label (nome dado ao container das chaves);
**Bytes a serem assinado ou string em Base64;
**Se os Bytes a serem assinados estao em base 64 (1 se esta em base64 e 0 caso contrario)
**Saida da assinatura( um char* allocado com tamanho minimo de 345)
**Tamanho alocado para a saida

*retorna SUCESS se ocorrou a assinatura
 */
STATUS assina(char* tokenLabel, char* Pin, char* ckaLabel, char* inData, int base64, char* saida, int saida_length);

#endif