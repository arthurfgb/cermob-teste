/* defines de unix cryptoki, direto da documentacao */

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


//define o máximo de objetos retornados em FindObjects
#define MAX_OBJECTS_RETURNED    30

#include <pkcs11.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
        printf("Erro C_FindObjectsInit com rv = %lu\n", rv);
        return rv;
    }

    rv = C_FindObjects(hSession, phPublicKey, MAX_OBJECTS_RETURNED, phPublicKeyCount);
    if(rv != CKR_OK) {
        printf("Erro C_FindObjects com rv = %lu\n", rv);
        return rv;
    }

    rv = C_FindObjectsFinal(hSession);
    if(rv != CKR_OK) {
        printf("Erro C_FindObjectsFinal com rv = %lu\n", rv);
        return rv;
    }


    free(template);

    return rv;
}
CK_RV getAtributosPK(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject){
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

                    printf("\n-------------------------------TEMPLATE----------------------------\n");
                    printf("\nLABEL:%s",(char*)template[4].pValue);
                    printf("\nTamanho:%lu\n",template[4].ulValueLen);
                }
                free(label);
            }
        return rv;
}



int searchTokenLabel(CK_SESSION_HANDLE hSession, CK_SLOT_ID_PTR pSlotList, CK_ULONG pulCount, char* tokenLabel)
{
    int i=0;
    CK_TOKEN_INFO tokenInfo;
    CK_SLOT_INFO slotInfo;

    for (i=0;i<pulCount;i++){

        if(C_GetSlotInfo(pSlotList[i],&slotInfo) != CKR_OK){
            printf("Slot invalido: %d", i);
            continue;
        }
        if(C_GetTokenInfo(pSlotList[i], &tokenInfo) != CKR_OK){
            printf("Token invalido: %d", i);
            continue;
        }

        if (strcmp(tokenInfo.label, tokenLabel)){

            printf(
                "\n************************************"
                "\nSlot ID: %d"
                "\nSlot Descricao: %.64s"
                "\nSlot manufacturerID: %.32s"
                "\nTOKEN LABEL:%.32s"
                "\n************************************\n", i, slotInfo.slotDescription, slotInfo.manufacturerID, tokenInfo.label);

                return 1;

        }

        return 0;
    }
}

CK_RV loginUser(CK_RV rv, CK_SESSION_HANDLE hSession, char* pin)
{
    CK_FLAGS flags = CKF_SERIAL_SESSION|CKF_RW_SESSION;
    rv = C_OpenSession(0,flags,0,NULL,&hSession);
                if(rv != CKR_OK){
                    printf("Erro ao abrir sessao\n\n");
                }

                rv = C_Login(hSession, CKU_USER,(CK_BYTE_PTR)pin ,strlen(pin));

                if (rv != CKR_OK) {
                        printf("PIN incorreto.\n\n");
                }
                else {
                    printf("Login Realizado com Sucesso!\n\n");
                }
                return rv;
}

CK_RV signData(
    CK_UTF8CHAR tokenLabel,
	char* ckaLabel,
	char* pin,
	char* inName)
{

}

int main(int argc, char** argv )
{

        CK_ULONG pulCount;
        CK_SLOT_ID_PTR pSlotList;
        CK_OBJECT_HANDLE_PTR phPublicKey;

        CK_SESSION_HANDLE hSession;


        CK_RV rv;


        CK_ULONG ulObjectCount;

        char* pin = "123456";

        if( (rv = C_Initialize(NULL_PTR)) != CKR_OK ){
            printf("Erro ao inicializar\n\n");
            return rv;
        }


        // retorna o numero de slots, mas não a lista deles
        rv = C_GetSlotList(CK_TRUE, NULL, &pulCount);

        if (rv != CKR_OK) {
            printf("Falha na leitura.\n\n");
            return rv;
        }
        else {

            pSlotList = (CK_SLOT_ID_PTR) malloc(pulCount*sizeof(CK_SLOT_ID));
            rv = C_GetSlotList(CK_TRUE, pSlotList, &pulCount);

            if (rv == CKR_OK) {

                char* tokenLabel =  "qualiconsult";

                if (searchTokenLabel(hSession, pSlotList, pulCount, tokenLabel) == 1)
                {
                    rv = loginUser(rv, hSession, pin);

                    if(rv == CKR_OK)
                    {
                        phPublicKey = (CK_OBJECT_HANDLE_PTR)malloc(sizeof(CK_OBJECT_HANDLE) * MAX_OBJECTS_RETURNED);

                        rv =  getPublicKeyObjectHandlers(hSession,phPublicKey,&ulObjectCount);
                        if(rv != CKR_OK) {
                            printf("Falha ao buscar publicKey");
                        }

                        rv = getAtributosPK(hSession, *(phPublicKey));

                        free(phPublicKey);
                    }
                }



            }
            else{

                printf("Erro na leitura do Slot!");
            }

            free(pSlotList);
        }
        C_CloseSession(hSession);
        C_Finalize(NULL_PTR);
        return rv;
}



