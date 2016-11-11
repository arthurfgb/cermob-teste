

//define o máximo de objetos retornados em FindObjects
#define MAX_OBJECTS_RETURNED    30


#include "assinaLib.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
//base64
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <assert.h>
#include <stdint.h>


//Calculates the length of a decoded string
size_t calcDecodeLength(const char* b64input) {
    size_t len = strlen(b64input),
    padding = 0;

    if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len-1] == '=') //last char is =
        padding = 1;

    return (len*3)/4 - padding;
}
//Decodes a base64 encoded string
int Base64Decode(char* b64message, unsigned char** buffer, size_t* length) {
    BIO *bio, *b64;

    int decodeLen = calcDecodeLength(b64message);
    *buffer = (unsigned char*)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
    *length = BIO_read(bio, *buffer, strlen(b64message));
    assert(*length == decodeLen); //length should equal decodeLen, else something went horribly wrong
    BIO_free_all(bio);

    return (0); //success
}


int Base64encode(char *encoded, const char *string, int len)
{
    static const char basis_64[] ="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i;
    char *p;

    p = encoded;
    for (i = 0; i < len - 2; i += 3) {
        *p++ = basis_64[(string[i] >> 2) & 0x3F];
        *p++ = basis_64[((string[i] & 0x3) << 4) |
            ((int) (string[i + 1] & 0xF0) >> 4)];
        *p++ = basis_64[((string[i + 1] & 0xF) << 2) |
            ((int) (string[i + 2] & 0xC0) >> 6)];
        *p++ = basis_64[string[i + 2] & 0x3F];
    }
    if (i < len) {
        *p++ = basis_64[(string[i] >> 2) & 0x3F];
        if (i == (len - 1)) {
            *p++ = basis_64[((string[i] & 0x3) << 4)];
            *p++ = '=';
        }
        else {
            *p++ = basis_64[((string[i] & 0x3) << 4) |
                ((int) (string[i + 1] & 0xF0) >> 4)];
            *p++ = basis_64[((string[i + 1] & 0xF) << 2)];
        }
        *p++ = '=';
    }

    *p++ = '\0';
    return p - encoded;
}

STATUS assinarBase64(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey, char* leitura, char** saida, int base64, int saida_length){

    CK_RV rv = CKR_OK;
    CK_BYTE_PTR inBuffer;
    CK_ULONG inBufferLen;
    CK_BYTE_PTR outBuffer;
    CK_ULONG outBufferLen;
    CK_MECHANISM mech = { CKM_RSA_PKCS, NULL_PTR, 0 };

    inBufferLen=strlen(leitura);

    inBuffer = (CK_BYTE_PTR)calloc(inBufferLen, sizeof(CK_BYTE));
    if (inBuffer == NULL) {
        fprintf(stderr, "Nao consegui alocar o buffer de entrada\n");
        return ERROR_ALLOC_BUFFER;
    }

    memcpy(inBuffer, leitura, inBufferLen);
    // se o conteudo do arquivo esta em base64 realiza o decode do conteudo
    if(base64==1){
        size_t sizeBase64;
        Base64Decode((char*)inBuffer,&inBuffer,&sizeBase64);
        inBufferLen=sizeBase64;
    }
    // se o mecanismo for CKM_RSA_PKCS, devemos calcular o hash e inseri-lo em uma
    // estrutura digestInfo antes de solicitar a assinatura ao cartao.
    static const CK_BYTE oidSHA1[] = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };
    unsigned char* hash = SHA1(inBuffer, inBufferLen, NULL);
    inBufferLen = sizeof(oidSHA1)+SHA_DIGEST_LENGTH;
    inBuffer = (CK_BYTE_PTR)realloc(inBuffer, (inBufferLen*sizeof(CK_BYTE)));
    memcpy(inBuffer, oidSHA1, sizeof(oidSHA1));
    memcpy(&inBuffer[sizeof(oidSHA1)], hash, SHA_DIGEST_LENGTH);

    // inicializa a assinatura
    rv = C_SignInit(hSession, &mech, hKey);
    if (rv != CKR_OK) {
        fprintf(stderr, "Nao consegui inicializar a assinatura\n");
        return ERROR_SIGN_INIT;
    }

    // passa o buffer de saida NULL para retornar o tamanho da assinatura
    rv = C_Sign(hSession, inBuffer, inBufferLen, NULL_PTR, &outBufferLen);
    if (rv != CKR_OK) {
        fprintf(stderr,"Nao consegui obter tamanho da assinatura\n");
        return ERROR_SIGN_SIZE;
    }

    // aloca o buffer que recebera a assinatura
    outBuffer = (CK_BYTE_PTR)calloc(outBufferLen, sizeof(CK_BYTE));
    if (outBuffer == NULL) {
        fprintf(stderr,"Nao consegui alocar o buffer de saida\n");
        return ERROR_ALLOC_BUFFER;
    }

    // realiza a assinatura
    rv = C_Sign(hSession, inBuffer, inBufferLen, outBuffer, &outBufferLen);
    if (rv != CKR_OK) {
        fprintf(stderr,"Nao consegui assinar\n");
        return ERROR_SIGN;
    }

    if(outBufferLen>saida_length){
        fprintf(stderr,"Tamanho da saida imcompativel com a assinatura\n");
        return ERROR_TAMANHO_SAIDA;
    }
    Base64encode(*saida, (char*)outBuffer, outBufferLen);

    if (inBuffer != NULL) {
        free(inBuffer);
    }
    if (outBuffer != NULL) {
        free(outBuffer);
    }

    return SUCESS;

}

CK_RV getPublicKeyObjectHandlers(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phPublicKey, CK_ULONG_PTR phPublicKeyCount) {

    CK_RV rv;
    //int i;
    CK_ATTRIBUTE_PTR template;
    CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
    template = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE));

    template[0].type = CKA_CLASS;
    template[0].pValue = &publicKeyClass;
    template[0].ulValueLen = sizeof(publicKeyClass);

    rv = C_FindObjectsInit(hSession, template, 1);
    if(rv != CKR_OK) {
        fprintf(stderr,"Erro C_FindObjectsInit com rv = %lu\n", rv);
        return rv;
    }

    rv = C_FindObjects(hSession, phPublicKey, MAX_OBJECTS_RETURNED, phPublicKeyCount);
    if(rv != CKR_OK) {
        fprintf(stderr,"Erro C_FindObjects com rv = %lu\n", rv);
        return rv;
    }

    rv = C_FindObjectsFinal(hSession);
    if(rv != CKR_OK) {
        fprintf(stderr,"Erro C_FindObjectsFinal com rv = %lu\n", rv);
        return rv;
    }


    free(template);

    return rv;
}

int getAtributosPK(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, char* cka_label){

    int retorno=0;
    CK_RV rv;

    CK_UTF8CHAR_PTR label = NULL;   //default: empty

    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, NULL, 0 },
        {CKA_TOKEN, NULL, 0 },
        {CKA_PRIVATE, NULL, 0},
        {CKA_MODIFIABLE, NULL, 0},
        {CKA_LABEL, NULL, 0}
    };

    rv = C_GetAttributeValue(hSession, hObject, template,sizeof(template)/sizeof(CK_ATTRIBUTE));
    if (rv == CKR_OK) {
        label       = (CK_UTF8CHAR_PTR)malloc(template[4].ulValueLen);
        template[4].pValue=label;
        rv = C_GetAttributeValue(hSession, hObject, template,sizeof(template)/sizeof(CK_ATTRIBUTE));
        if (rv == CKR_OK) {
            if(strcmp((char*)template[4].pValue,cka_label)==0){
                retorno=1;
            }
        }
        free(label);
    }
    return retorno;
}

int searchTokenLabel(CK_SESSION_HANDLE hSession, CK_SLOT_ID_PTR pSlotList, CK_ULONG pulCount, char* tokenLabel)
{
    int i=0;
    CK_TOKEN_INFO tokenInfo;
    CK_SLOT_INFO slotInfo;

    for (i=0;i<pulCount;i++){

        if(C_GetSlotInfo(pSlotList[i],&slotInfo) != CKR_OK){
            fprintf(stderr,"Slot invalido: %d", i);
            continue;
        }
        if(C_GetTokenInfo(pSlotList[i], &tokenInfo) != CKR_OK){
            fprintf(stderr,"Token invalido: %d", i);
            continue;
        }

        if (strcmp((char*)tokenInfo.label, tokenLabel) == 0){

            return 1;
        }

    }
    return 0;
}

CK_RV loginUser(CK_RV rv, CK_SESSION_HANDLE_PTR hSession_PTR, char* pin)
{
    CK_FLAGS flags = CKF_SERIAL_SESSION|CKF_RW_SESSION;
    rv = C_OpenSession(0,flags,0,NULL,hSession_PTR);
    if(rv != CKR_OK){
        fprintf(stderr,"\nErro ao abrir sessao\n\n");
        return rv;
    }

    rv = C_Login(*hSession_PTR, CKU_USER,(CK_BYTE_PTR)pin ,strlen(pin));

    if (rv != CKR_OK) {
        fprintf(stderr,"\nPIN incorreto.\n\n");
        return rv;
    }
    return rv;
}

STATUS assina(char* tokenLabel, char* Pin, char* ckaLabel, char* inData, int base64, char* saida, int saida_length){

    CK_RV rv = CKR_OK;
    CK_ULONG pulCount;
    CK_SLOT_ID_PTR pSlotList;
    CK_OBJECT_HANDLE_PTR phPublicKey;
    CK_SESSION_HANDLE hSession;
    CK_ULONG ulObjectCount;

    STATUS st=SUCESS;


    if( (rv = C_Initialize(NULL_PTR)) != CKR_OK ){
        fprintf(stderr,"Erro ao inicializar\n\n");
        return ERROR_INIT;
    }
    else{

            // retorna o numero de slots, mas não a lista deles
        rv = C_GetSlotList(CK_TRUE, NULL, &pulCount);

        if (rv != CKR_OK) {
            fprintf(stderr,"Falha na leitura.\n\n");
            return ERROR_LEITURA_SLOT;
        }
        else {

            pSlotList = (CK_SLOT_ID_PTR) malloc(pulCount*sizeof(CK_SLOT_ID));
            rv = C_GetSlotList(CK_TRUE, pSlotList, &pulCount);

            if (rv != CKR_OK) {
                fprintf(stderr,"Erro na leitura do Slot!\n");
                return ERROR_LEITURA_SLOT;
            }

            else{
                if (searchTokenLabel(hSession, pSlotList, pulCount, tokenLabel) == 0){
                    fprintf(stderr,"Token nao encontrado!\n");
                    return ERROR_NF_TOKEN;
                }
                else{

                    rv = loginUser(rv, &hSession, Pin);

                    if(rv != CKR_OK){
                        fprintf(stderr,"Falha ao buscar publicKey");
                        return ERROR_LOGIN;
                    }
                    phPublicKey = (CK_OBJECT_HANDLE_PTR)malloc(sizeof(CK_OBJECT_HANDLE) * MAX_OBJECTS_RETURNED);

                    rv =  getPublicKeyObjectHandlers(hSession,phPublicKey,&ulObjectCount);
                    if(rv != CKR_OK) {
                        fprintf(stderr,"Falha ao buscar publicKey");
                        return ERROR_PUBLICKEY;
                    }
                                //encontra a chave com a CKA_LABEL compativel
                    int i=0;
                    while(i<ulObjectCount){
                        if(getAtributosPK(hSession, *(phPublicKey+i),ckaLabel)==1){
                            break;
                        }
                        i++;
                    }
                                // não encotrou CKA_LABEL compativel
                    if(i==ulObjectCount){
                        fprintf(stderr,"\nCKA_LABEL não encontrado!\n");
                        return ERROR_NF_CKA;
                    }
                    else{
                        st =assinarBase64(hSession,*(phPublicKey+i), inData, &saida ,base64,saida_length);
                        if( st != SUCESS ){
                            fprintf(stderr,"\nErro ao Assinar rv=%lu!\n",rv);
                            return st;
                        }
                        else{
                            fprintf(stderr,"\nAssinatura realizada com sucesso!\n");
                            st=SUCESS;
                        }
                    }
                    free(phPublicKey);

                }

            }

            free(pSlotList);
        }
    }

    C_CloseSession(hSession);
    C_Finalize(NULL_PTR);

    return st;
}
