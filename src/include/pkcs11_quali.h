/**
 * pkcs11_quali.h include file for extra PKCS#11 functions. 2008 May 06 
 * @author: Matheus Ferreira Ribeiro
 * 			Joao Victor dos Anjos Barbara 			
 */

#include "pkcs11.h"

/* General-purpose */

// TYPES
/*
 *  CK_EXT_FUNCTION_LIST eh uma estrutura que comporta
 *  ponteiros para todas as funcoes adjacentes da PKCS#11
 *  desenvolvidas pela empresa QualiConsult
 */

typedef struct CK_EXT_FUNCTION_LIST CK_EXT_FUNCTION_LIST;

typedef CK_EXT_FUNCTION_LIST CK_PTR CK_EXT_FUNCTION_LIST_PTR;

typedef CK_EXT_FUNCTION_LIST_PTR CK_PTR CK_EXT_FUNCTION_LIST_PTR_PTR;

// POINTER FUNCTIONS
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_UnblockPIN)
(
  CK_SESSION_HANDLE hSession,
  CK_USER_TYPE userType,
  CK_UTF8CHAR_PTR pPuk,
  CK_ULONG ulPukLen
);

typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_SetUnblockPIN)
(
  CK_SESSION_HANDLE hSession,
  CK_USER_TYPE userType,
  CK_UTF8CHAR_PTR pOldPin,
  CK_ULONG ulOldLen,
  CK_UTF8CHAR_PTR pNewPin,
  CK_ULONG ulNewLen
);

typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_InitPINPUK)
(
  CK_SESSION_HANDLE hSession,
  CK_UTF8CHAR_PTR pNewPin,
  CK_ULONG ulNewPinLen,
  CK_UTF8CHAR_PTR pNewPuk,
  CK_ULONG ulNewPukLen
);

typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_GetExtFunctionList)
(
  CK_EXT_FUNCTION_LIST_PTR_PTR ppExtFunctionList
);

struct CK_EXT_FUNCTION_LIST {
	CK_FUNCTION_LIST_PTR pFunctionList;
	CK_C_UnblockPIN C_UnblockPIN;
	CK_C_SetUnblockPIN C_SetUnblockPIN;
	CK_C_GetExtFunctionList C_GetExtFunctionList;
	CK_C_InitPINPUK C_InitPINPUK;
};

// FUNCTIONS
/* C_UnblockPIN unlock the user pin. */
extern CK_DECLARE_FUNCTION(CK_RV, C_UnblockPIN)
(
  CK_SESSION_HANDLE hSession,
  CK_USER_TYPE userType,
  CK_UTF8CHAR_PTR pPuk,
  CK_ULONG ulPukLen
);

/* C_SetUnblockPIN */
extern CK_DECLARE_FUNCTION(CK_RV, C_SetUnblockPIN)
(
  CK_SESSION_HANDLE hSession,
  CK_USER_TYPE userType,
  CK_UTF8CHAR_PTR pOldPin,
  CK_ULONG ulOldLen,
  CK_UTF8CHAR_PTR pNewPin,
  CK_ULONG ulNewLen
);

/* C_InitPINPUK */
extern CK_DECLARE_FUNCTION(CK_RV, C_InitPINPUK)
(
  CK_SESSION_HANDLE hSession,
  CK_UTF8CHAR_PTR pNewPin,
  CK_ULONG ulNewPinLen,
  CK_UTF8CHAR_PTR pNewPuk,
  CK_ULONG ulNewPukLen
);

/* C_GetFunctionListExt */
extern CK_DECLARE_FUNCTION(CK_RV, C_GetExtFunctionList)
(
  CK_EXT_FUNCTION_LIST_PTR_PTR ppExtFunctionList
);

