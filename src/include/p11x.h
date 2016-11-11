#ifndef _p11x_h
#define _p11x_h

/** p11x.h
  * ======
  * Matheus Ribeiro <mfribeiro@gmail.com>
  *
  * This include files has functions from all p11x sources.
  * They are used only internally by the library, and should not be exported in any way.
  * Files named p11x_* are specific files. They implement Cryptoki functionalities.
  * All p11x_ files should include this. 
  */


#include <cryptoki.h>
#include <assert.h>
#include "crackcert.h"

// just to show what a parameter is used for
#define IN
#define OUT

/**********************************************************************/
/** p11x_key.c functions */


/** Create the key info for a key object. 
  */
CK_RV object_CreateKeyInfo(
	IN 	P11_Session *session, 
	OUT CK_OBJECT_HANDLE *hObject, 
	IN	MSCKeyInfo *pKeyInfo,
	IN	CK_ATTRIBUTE *pKeyTemplate,
	IN	CK_ULONG ulKeyAttributeCount
);

/** Updates the key info of a key object. KeyInfo comes from MUSCLE info directly.
  * old value is erased and freed.
  */
CK_RV key_UpdateInfo(
	IN	P11_Session *session, 
	IN	CK_OBJECT_HANDLE *hObject, 
	IN	MSCKeyInfo *pKeyInfo
);

/** Infer key attributes */
CK_RV key_InferAttributes(
	IN 	P11_Session *session, 
	IN	P11_Object *object
);

/** Writes key attributes to token */
CK_RV key_WriteAttributes(
	IN	P11_Session *session, 
	IN	P11_Object *key
);

/** Generates a pair of RSA keys, using template for key attributes. 
  * Returns both key handles in last 2 parameters.
  */
CK_RV key_RSAGenPair(
	IN	P11_Session *session,
	IN	CK_ATTRIBUTE *pPublicKeyTemplate,
	IN	CK_ULONG ulPublicKeyAttributeCount,
	IN	CK_ATTRIBUTE *pPrivateKeyTemplate,
	IN	CK_ULONG ulPrivateKeyAttributeCount,
	OUT	CK_OBJECT_HANDLE *phPublicKey,
	OUT	CK_OBJECT_HANDLE *phPrivateKey
);

/** Creates public key. Used when importing keys?????? */
CK_RV key_CreatePublic(
	P11_Session *session, 
	P11_Object *object
);

/** Creates private key, used then importing key?????? */
CK_RV key_CreatePrivate(
	P11_Session *session, 
	P11_Object *object
);

void key_AddDefaults(
	P11_Object *object
);

/***************************************************/
/** p11x_cert functions */

CK_RV cert_Create(P11_Session *session, P11_Object *object);

CK_RV cert_GetSerial(CK_BYTE *cert, CK_ULONG cert_size, CK_BYTE *out, CK_ULONG *out_len);

CK_RV cert_GetSubject(CK_BYTE *cert, CK_ULONG cert_size, CK_BYTE *out, CK_ULONG *out_len);

CK_RV cert_GetIssuer(CK_BYTE *cert, CK_ULONG cert_size, CK_BYTE *out, CK_ULONG *out_len);

CK_RV cert_GetModulus(CK_BYTE *cert, CK_ULONG cert_size, CK_BYTE *out, CK_ULONG *out_len);

CK_RV cert_GetPubExponent(CK_BYTE *cert, CK_ULONG cert_size, CK_BYTE *out, CK_ULONG *out_len);

void cert_AddDefaults(P11_Object *object);

/**********************************************************************/
/** p11x_object.c functions */

/** Generates object id */
CK_RV object_GetId(P11_Object *object, CK_BYTE_PTR id, CK_ULONG_PTR pIdLen);

/** Free all objects in given slot */
void object_FreeAllObjects(
	IN	CK_SLOT_ID slotID, 
	IN	P11_Object *list
);
	
/** Free an object from token obj list */
void object_FreeObject(
	IN	CK_SLOT_ID slotID, 
	IN	P11_Object *object
);

/** Free all attributes from list 
 * TODO: shouldnt we pass the object instead of the list???
 */
void object_FreeAllAttributes(
	IN P11_Attrib *list
);

CK_RV object_AddObject(CK_SLOT_ID slotID, CK_OBJECT_HANDLE *phObject);
CK_RV object_UpdateInfo(P11_Session *session, CK_OBJECT_HANDLE *hObject, MSCObjectInfo *pObjectInfo);
CK_RV object_FreeTokenObjects(CK_SLOT_ID slotID);
CK_RV object_GetAttrib(CK_ATTRIBUTE_TYPE type, P11_Object *object, P11_Attrib **attrib);
CK_RV object_SetAttrib(P11_Object *object, CK_ATTRIBUTE *attrib);
CK_RV object_AddAttribute(P11_Object *object, CK_ATTRIBUTE_TYPE type, CK_BBOOL token, CK_BYTE *value, CK_ULONG value_len, P11_Attrib **attrib);
CK_RV object_AddBoolAttribute(CK_ATTRIBUTE_TYPE type, CK_BBOOL value, P11_Object *object);
CK_RV object_MatchAttrib(CK_ATTRIBUTE *attrib, P11_Object *object);
void object_LogObjects(CK_SLOT_ID slotID);
void object_LogObject(P11_Object *object);
void object_LogAttribute(CK_ATTRIBUTE *attrib);
void object_BinToHex(CK_BYTE *data, CK_ULONG data_len, CK_BYTE *out);
CK_RV object_AddAttributes(P11_Object *object, CK_BYTE *data, CK_ULONG len);
CK_RV object_ReadAttributes(P11_Session *session, CK_BYTE *obj_id, P11_Object *object);
CK_RV object_InferAttributes(P11_Session *session, P11_Object *object);
CK_RV object_InferObjAttributes(P11_Session *session, P11_Object *object);
CK_RV object_WriteValueAndAttributes(P11_Session *session, P11_Object *object);
CK_RV object_WriteAttributes(P11_Session *session, P11_Object *object);
CK_RV object_InferClassAttributes(P11_Session *session, P11_Object *object);
CK_RV object_CreateObject(P11_Session *session, P11_Object *object);
CK_ULONG object_MapPIN(CK_ULONG pinNum);
CK_ULONG object_UserMode(P11_Session *session);
void object_AddDefaultAttributes(P11_Object *object);
CK_BBOOL object_IsVisible(P11_Object *object, P11_Session *session);
void object_AddMscObject(CK_SLOT_ID slotID, P11_Object *object);
void object_AddMscKey(CK_SLOT_ID slotID, P11_Object *object);
void object_RemoveObject(CK_SLOT_ID slotID, P11_Object *object);
void object_RemoveMscObject(CK_SLOT_ID slotID, P11_Object *object);
void object_RemoveMscKey(CK_SLOT_ID slotID, P11_Object *object);

/** Returns if an object is a session object or not. */
CK_BBOOL object_IsSessionObject(P11_Object *object);

/** Returns an object from an object handle, NULL if handle is invalid */
P11_Object *object_LookupObject(CK_OBJECT_HANDLE hObject);

/** Returns object size */
CK_ULONG object_GetSize(P11_Object *object);

CK_ULONG object_GetAttributesSize(P11_Object *object);

/***********************************************************/
/** p11x_cert.c functions */

/** Gets certificate serial number.
  * @param cert the certificate to get number from
  * @param cert_size certificate size
  * @param out output buffer, where serial will be placed.
  * @param out_len output buffer length, modified to hold the serial
  * @return ...
  */
CK_RV cert_GetSerial(
	IN CK_BYTE *cert, 
	IN CK_ULONG cert_size, 
	OUT CK_BYTE *out, 
	IN OUT CK_ULONG *out_len
);


CK_RV cert_GetSubject(
	CK_BYTE *cert, 
	CK_ULONG cert_size, 
	CK_BYTE *out, 
	CK_ULONG *out_len
);

CK_RV cert_GetIssuer(
	CK_BYTE *cert, 
	CK_ULONG cert_size, 
	CK_BYTE *out, 
	CK_ULONG *out_len
);

CK_RV cert_Create(
	P11_Session *session, 
	P11_Object *object
); 


/** p11x_slot.c functions */
CK_RV slot_BeginTransaction(CK_ULONG slotID);
CK_RV slot_EndTransaction(CK_ULONG slotID, CK_ULONG action);
CK_BBOOL slot_CheckSession(CK_ULONG slotID);
CK_BBOOL slot_CheckRWSOsession(CK_ULONG slotID);
CK_RV slot_EstablishConnection(CK_ULONG slotID);
CK_RV slot_ReleaseConnection(CK_ULONG slotID);
CK_RV slot_UpdateSlot(CK_ULONG slotID);
CK_BBOOL slot_VerifyEvent(CK_ULONG slotID);
CK_RV slot_VerifyPIN(CK_SLOT_ID slotID, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
CK_ULONG slot_MinRSAKeySize(MSCULong32 cap);
CK_ULONG slot_MaxRSAKeySize(MSCULong32 cap);
CK_RV slot_UpdateMechanisms(CK_ULONG slotID);
CK_ULONG slot_MechanismCount(P11_MechInfo *mech);
void slot_FreeAllMechanisms(P11_MechInfo *list);
CK_RV slot_AddMechanism(P11_Slot *slot, CK_MECHANISM_TYPE type, P11_MechInfo **mech_info);
CK_RV slot_UpdateSlotList();
CK_RV slot_FreeAllSlots();
CK_RV slot_DisconnectSlot(CK_ULONG slotID, CK_ULONG action);
CK_RV slot_PublicMode(CK_ULONG slotID);
CK_RV slot_UserMode(CK_ULONG slotID);
CK_RV slot_SOMode(CK_ULONG slotID);
CK_BBOOL slot_IsLogged(P11_Slot *slot);
P11_Slot *slot_WaitEvent(CK_BBOOL block);
CK_RV slot_GetId(P11_Slot *slot, CK_SLOT_ID_PTR idAdd);
void slot_GetInfos(MSCTokenInfo **infoAdd, CK_ULONG *infoSzAdd);
void slot_CloseAllSessions(P11_Slot *slot);

/** adds a session to the given slot, returning handle and structure */
CK_RV slot_AddSession(
	IN P11_Slot *slot,
	OUT CK_SESSION_HANDLE *pHandle, 
	OUT P11_Session **pSession
);

/** This function return CK_TRUE if a token is present in the slot slotID, CK_FALSE otherwise*/
CK_BBOOL slot_TokenPresent(IN CK_ULONG slotID);
CK_BBOOL slot_HasROSession(CK_ULONG slotId);
	
/** Returns the slot structure handled by the given ID */
P11_Slot *slot_GetSlotByID(CK_SLOT_ID slotID);

/** gets the token infos of all P11 slots as an array. Pointer addressed by tAdd must be freed, otherwise will leak
* @param out tAdd address of a MSCTokenInfo pointer (will be allocated)
* @param out tLenAdd address of a MSCULong32 to receive the number of tokens in array
*/
void slot_GetInfos(MSCTokenInfo **tAdd, MSCULong32 *tLenAdd);

/* jvictor */
CK_ULONG slot_UnblockPIN
(
	CK_SLOT_ID slotID, 
	CK_USER_TYPE userType, 
	CK_UTF8CHAR_PTR pPuk, 
	CK_ULONG ulPukLen
);

/** p11x_session.c functions */

/** Returns a pointer to the session from Pkcs11 global structure. */
P11_Session *session_LookupSessionHash(
	IN	CK_SESSION_HANDLE handle
);

/** Returns a pointer to the session from Pkcs11 global structure. Also update the session slot. */
CK_RV session_LookupSessionUpdateSlot(
	IN	CK_SESSION_HANDLE handle,
	IN	P11_Session** session
);

/** frees a session */
CK_RV session_FreeSession(
	IN 	P11_Session *session
);

/** checks if a session is RO, returning CK_TRUE in this case */
CK_BBOOL session_IsReadOnly(
	IN	P11_Session *sp
);

/** Refresh objects */
CK_RV session_UpdateObjects(
	IN P11_Session *session,
	IN CK_FLAGS refreshObjectFlags
);

/** Reads all token object to session structure. */
CK_RV session_RereadObjects(
	IN P11_Session *sp
);

/** p11x_token functions. */

CK_RV token_Update(CK_ULONG slotID);
CK_RV token_UpdateInfo(CK_ULONG slotID);
CK_RV token_UpdateObjectInfo(CK_ULONG slotID);
CK_RV token_UpdateAll();
void token_BlankInfo(CK_TOKEN_INFO *token_info);

/** p11x_plog.c  functions */
void plog_Start(char *func);
void plog_End(char *func, CK_RV rv);
void plog_Err(char *msg, char *file, CK_LONG line);
void plog_Log(CK_ULONG level, char *format, ...);

/** p11x_template.c functions */

/** returns an attribute of the given type in template */
CK_RV template_GetAttrib(
		IN CK_ATTRIBUTE *aTemplate,     //< the attribute template
		IN CK_ULONG attrib_count,      //< number of attributes in template
		OUT CK_ATTRIBUTE **attrib_out,   //< pointer to attribute, which will receive the answer, NULL otherwise
		IN CK_ATTRIBUTE_TYPE type     //< the attribute type were looking for
);

/** returns CK_TRUE if template has the attribute type */
CK_BBOOL template_HasAttrib(
		IN CK_ATTRIBUTE *aTemplate,     //< the attribute template
		IN CK_ULONG attrib_count,       //< number of attribs count
		IN CK_ATTRIBUTE_TYPE type     //< attribute type we are looking for
);


/** p11x_state functions. Functions related to the global st state variable. */
CK_RV state_Init();
CK_RV state_Free();

/* p11x_sys.c functions */

/** Inicializa o timestamp da aplicacao*/

void sys_InitializeTimestamp();

/** retorna o timestamp referente a inicializacao da aplicacao */
CK_ULONG sys_Timestamp();

/** verifica o timestamp de um slot logado da aplicacao */
CK_RV slot_VerifyTimestamp(P11_Slot* slot, CK_ULONG currentTimestamp);

/** verifica e atualiza o timestamp de um slot logado da aplicacao */
CK_RV slot_VerifyAndUpdateTimestamp(P11_Slot* slot, CK_ULONG currentTimestamp);

#undef IN
#undef OUT
#endif

