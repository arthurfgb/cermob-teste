/******************************************************************************
** 
**  $Id: cryptoki.h,v 1.3 2005/03/22 22:03:43 ko189283 Exp $
**
**  Package: PKCS-11
**  Author : Chris Osgood <oznet@mac.com>
**  License: Copyright (C) 2002 Schlumberger Network Solutions
**           <http://www.slb.com/sns>
**  Purpose: Main cryptoki header (include in all source files)
** 
******************************************************************************/
#ifndef __CRYPTOKI_H__
#define __CRYPTOKI_H__

/******************************************************************************
** Include all "standard" RSA PKCS #11 headers
******************************************************************************/
#ifndef WIN32
#include "cryptoki_unix.h"
#else
#include "cryptoki_win32.h"
#endif
#include "qualipkcs11.h"


/******************************************************************************
** Regular headers
******************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "musclecard.h"
#include "sha1.h"

#include <sys/types.h>

/******************************************************************************
** Logging (OSX needs -no-cpp-precomp for VA_ARGS to work)
******************************************************************************/
#ifndef NO_LOG
#define P11_LOG_START(x)        plog_Start(x)
#define P11_LOG_END(x)          plog_End(x,rv)
#define P11_ERR(x)              plog_Err(x,__FILE__,__LINE__)
#else
#define P11_LOG_START(x)
#define P11_LOG_END(x)
#define P11_ERR(x)
#endif

#define LOG_LOW     0
#define LOG_MED     5
#define LOG_HIGH    9


/******************************************************************************
** Error checking macros
******************************************************************************/
#define PCSC_ERROR_NOLOG(x)    ((x) != SCARD_S_SUCCESS)
#define CKR_ERROR_NOLOG(x)     ((x) != CKR_OK)
#define MSC_ERROR_NOLOG(x)     ((x) != MSC_SUCCESS)

#ifndef NO_LOG
#define PCSC_ERROR(x)       ((error_LogCmd((x),SCARD_S_SUCCESS,(CK_CHAR*)__FILE__,__LINE__,pcsc_stringify_error)) != SCARD_S_SUCCESS)
#define CKR_ERROR(x)        ((error_LogCmd((x),CKR_OK,(CK_CHAR*)__FILE__,__LINE__,error_Stringify)) != CKR_OK)
#define MSC_ERROR(x)        ((error_LogCmd((x),MSC_SUCCESS,(CK_CHAR*)__FILE__,__LINE__,msc_error)) != MSC_SUCCESS)
#else
#define PCSC_ERROR(x)       PCSC_ERROR_NOLOG(x)
#define CKR_ERROR(x)        CKR_ERROR_NOLOG(x)
#define MSC_ERROR(x)        MSC_ERROR_NOLOG(x)
#endif

#define INVALID_SLOT        ((st.slots == NULL) || (slotID < 0) || (slotID >= st.slot_count))

#define INVALID_OBJECT      (!(hObject && (((P11_Object *)hObject)->check == (P11_Object *)hObject)))
#define READ_ONLY_SESSION   0 /* Fixme: implement this */

#define USER_MODE            (session && (((session)->session.state == CKS_RO_USER_FUNCTIONS) || ((session)->session.state == CKS_RW_USER_FUNCTIONS)))


/******************************************************************************
** Utility macros
******************************************************************************/
#ifndef max
#define max(a,b)            (((a)>(b))?(a):(b))
#endif
#ifndef min
#define min(a,b)            (((a)<(b))?(a):(b))
#endif

#define P11_MAX_ULONG ((CK_ULONG)(~0))

/******************************************************************************
** Library information
******************************************************************************/
#define PKCS11_MAJOR			0x02
#define PKCS11_MINOR			0x02
#define PKCS11_LIB_MAJOR        ((QUALIPKCS11_VERSAO_MAIOR << 4) | (QUALIPKCS11_VERSAO_DEPENDENCIAS))
#define PKCS11_LIB_MINOR        ((QUALIPKCS11_VERSAO_MENOR << 4) | (QUALIPKCS11_VERSAO_LANCAMENTO))
#define PKCS11_MFR_ID           "QualiConsult"
#define PKCS11_DESC             "Quali PKCS #11 module"
#define PKCS11_SO_PIN_NUM		0
#define PKCS11_USER_PIN_NUM		1

#if WIN32
#define PKCS11_LOG_FILENAME		"c:\\PKCS11.log"
#else
#define PKCS11_LOG_FILENAME     "/var/tmp/PKCS11.log"
#endif

/******************************************************************************
** Token information
******************************************************************************/
#define MIN_PIN_LEN				1
#define MAX_PIN_LEN				16

/*****************************************************************************
** Session information
*****************************************************************************/
#define PKCS11_LOGIN_TIMEOUT	600      /* timeout session in seconds  */

/******************************************************************************
** P11 typedefs
******************************************************************************/

//typedef void* P11_Mutex;

/* PKCS #11 mechanism info list */
typedef struct _P11_MechInfo
{
    CK_MECHANISM_TYPE type;         /* Mechanism type   */
    CK_MECHANISM_INFO info;         /* Mechanism info   */

    struct _P11_MechInfo *prev;
    struct _P11_MechInfo *next;
} P11_MechInfo;

/* PKCS #11 object attribute */
typedef struct _P11_Attrib
{
    CK_ATTRIBUTE attrib;            /* Object attribute data        */
    CK_BBOOL token;                 /* Store attribute on token?    */

    struct _P11_Attrib *prev;
    struct _P11_Attrib *next;
} P11_Attrib;

// avoid circular dependencies
typedef struct _P11_Session* P11_SessionPtr;

/* A muscle object info */
typedef struct _P11_MuscleObject
{
	MSCObjectInfo obj;
	CK_BBOOL visible;
	CK_BBOOL refreshed;

	struct _P11_MuscleObject *prev;
	struct _P11_MuscleObject *next;
	struct _P11_MuscleObject *check;
} P11_MuscleObject;

/* A muscle key info */
typedef struct _P11_MuscleKey
{
	MSCKeyInfo key;
	CK_BBOOL visible;
	CK_BBOOL refreshed;

	struct _P11_MuscleKey *prev;
	struct _P11_MuscleKey *next;
	struct _P11_MuscleKey *check;
} P11_MuscleKey;

/* A PKCS #11 object (session or on-card) */
typedef struct _P11_Object
{
	P11_SessionPtr session;         /* Session that owns this object. Not used with token objects               */
	P11_Attrib *attrib;             /* List of attributes                                                       */
	MSCObjectInfo *msc_obj;      /* On-token object info (both MSC objects).  Not used with session objects  */
	MSCKeyInfo *msc_key;            /* On-token key info.  Not used with session objects                        */

	struct _P11_Object *prev;
	struct _P11_Object *next;
	struct _P11_Object *check;      /* Should contain the memory address of this structure  */
} P11_Object;

/* Cached PIN */
typedef struct _P11_Pin
{
    CK_BYTE pin[256];               /* Fixme: don't hardcode, use MAX_Musclecard_PIN)   */
    CK_ULONG pin_size;
} P11_Pin;

/* A session with one slot.  */
typedef struct _P11_Session
{
    CK_SESSION_INFO session;        /* CK session info                   */
    CK_VOID_PTR application;        /* Passed to notify callback         */
    CK_NOTIFY notify;               /* Notify callback                   */

    P11_Object *search_object;      /* Current object (used with C_FindObjects) */
    CK_ATTRIBUTE *search_attrib;    /* Current search attributes                */
    CK_ULONG search_attrib_count;   /* Current search attribute count           */

    CK_MECHANISM sign_mech;         /* Active signing mechanism */
    CK_OBJECT_HANDLE sign_key;      /* Active signing key       */
#if SIGN_UPDATE
	SHA1Context hash_ctx;
	CK_ULONG hash_initialized;
	CK_BYTE_PTR sign_data_buffer;
	CK_ULONG sign_data_buffer_len;
#endif

    struct _P11_Session *prev;
    struct _P11_Session *next;
    struct _P11_Session *check;     /* Should contain the memory address of this structure  */

    /* Added by Netscape */
	CK_SESSION_HANDLE handle;       /* session handle, index into hashtable */
	struct _P11_Session *hnext;     /* next entry in hash table */
    /* End of additions */
} P11_Session;

/* A card reader.  */
typedef struct
{
	CK_ULONG eventFlags;			/* internal flag for slot events     */
    CK_ULONG pin_state;             /* NONE (0), USER (1), SO (2)        */
    CK_SLOT_INFO slot_info;         /* CK slot structure                 */
	CK_TOKEN_INFO token_info;       /* CK token structure                */
    P11_Object *objects;            /* List of objects                   */
    P11_MechInfo *mechanisms;       /* List of mechanisms                */
    CK_FLAGS refreshObjectFlags;    /* Some information bits (see below) */
    MSCTokenConnection conn;        /* all muscle information is here      */
    P11_Session *sessions;          /* List of all sessions with this slot */
	CK_ULONG evCount;				/* event counter of the last slot refresh */
	CK_BBOOL tokenValid;			/* if not set, token is invalid */
	P11_MuscleObject *mscObjs;		/* list of muscle object infos */
	P11_MuscleKey *mscKeys;			/* list of muscle key infos */
	CK_ULONG timestamp;				/* o timestamp da ultima utilizacao da sessao */
} P11_Slot;

/** possible values for eventFlags in P11_Slot */
#define	EVENT_NO_EVENT				0x0000
#define	EVENT_CARD_INSERTED_REMOVED	0x0001
#define	EVENT_SESSION_TIMEOUT		0x0002

/** internal information about the slot (slots refreshObjectFlags flag) */
#define P11_SLOT_REREAD_OBJECTS		0x01	///< indicates all objects must be reread from slot

#define REF_SET_PRIV_VISIBLE		0x01
#define REF_SET_PRIV_INVISIBLE		0x02
#define REF_ADD_NEW_OBJ				0x04
#define REF_REM_OBJ					0x08
#define REF_REFRESH_CERTS			0x10
#define REF_REFRESH_KEYS			0x20
#define REF_REFRESH_DATA			0x40
#define REF_REFRESH_ALL				0x80

/* Changes from Netscape
 * Number of slots in the session has table.
 * Keep it small for now, since we don't expect there to be too many
 * sessions on a little smart card.
 */

#define NUM_SESSION_HASH_SLOTS  13

/* End of Netscape changes */


/* Master PKCS #11 module state information */
typedef struct
{
    CK_ULONG initialized;           /** Has Cryptoki been intialized                              */
    P11_Slot *slots;                /** Array of all slots TODO tirar isso                        */
    CK_ULONG slot_count;            /** Number of slots in array                                  */
    CK_VOID_PTR log_lock;           /** Log mutex                                                 */
    CK_VOID_PTR async_lock;         /** Asychronous mutex                                         */
    CK_BBOOL native_locks;          /** Library can use native locks                              */
    CK_BBOOL create_threads;        /** Library can create threads                                */
	CK_BBOOL multithread_access;    /** Library will be accessed by multiple threads              */
	CK_VOID_PTR wfse_lock;			/** mutex for the WaitForSlotEvent */
	CK_BBOOL runningWaitForSlotEvent;	/** flag for mutex of Wait|ForSlotEvent */
	CK_ULONG initTimestamp;			/** timestamp do incio da aplicacao */
	CK_ULONG timestampIval;         /** intervalo de timestamp maximo por sessao. */
	
	/* Netscape changes */

	CK_SESSION_HANDLE last_session_handle;  
	P11_Session *session_hash[NUM_SESSION_HASH_SLOTS];

	/* End of Netscape changes */

} P11_State;

/* Global state variable : see p11x_state.c */
extern P11_State st;

/******************************************************************************
** Prototypes (extensions in addition to the standard PKCS #11 functions)
******************************************************************************/

/* p11x_async.c */
// void *async_WatchSlots(void *parent_pid);
// void async_SignalHandler(int sig);

/* p11_crypt.c  (Netscape addition) */
int padRSAType1(CK_BYTE* to, CK_ULONG toLen, CK_BYTE *from, CK_ULONG fromLen);

/* p11x_debug.c */
void debug_Init();
void debug_CheckCorrupt(size_t i);
void debug_Check();
void *debug_Malloc(size_t size, int line, char *file);
void debug_Free(void *ptr, int line, char *file);
void *debug_Calloc(size_t size, int line, char *file);

/* p11x_error.c */
CK_RV error_LogCmd(CK_RV err, CK_RV cond, CK_CHAR *file, CK_LONG line, char *(*stringifyFn)(CK_RV));
 char *error_Stringify(CK_RV rv);

/* p11x_mutex.c */
CK_RV mutex_UseNativeFunctions();
CK_RV mutex_UseExternalFunctions(
	CK_CREATEMUTEX fn_createmutex, 
	CK_DESTROYMUTEX fn_destroymutex, 
	CK_LOCKMUTEX fn_lockmutex,
	CK_UNLOCKMUTEX fn_unlockmutex
);
CK_RV mutex_Finalize();
CK_RV mutex_Init(CK_VOID_PTR *mutex);
CK_RV mutex_Destroy(CK_VOID_PTR mutex);
CK_RV mutex_Lock(CK_VOID_PTR mutex);
CK_RV mutex_Unlock(CK_VOID_PTR mutex);
	
/* p11x_util.c */
    void util_byterev(CK_BYTE *data, CK_ULONG len);
CK_ULONG util_strpadlen(CK_CHAR *string, CK_ULONG max_len);
   CK_RV util_PadStrSet(CK_CHAR *string, CK_CHAR *value, CK_ULONG size);
   CK_RV util_StripPKCS1(CK_BYTE *data, CK_ULONG len, CK_BYTE *output, CK_ULONG *out_len);
#ifndef __USE_GNU
#ifndef WIN32
   size_t strnlen(__const char *__string, size_t __maxlen);
#else
   size_t strnlen(const char *__string, size_t __maxlen);
#endif
#endif /* __USE_GNU */
CK_BBOOL util_IsLittleEndian();

/* p11x_msc.c */
#include "p11x_msc.h"


/******************************************************************************
** dmalloc debugging
******************************************************************************/
#ifdef DMALLOC
#include "dmalloc.h"
#endif


#endif /* __CRYPTOKI_H__ */
