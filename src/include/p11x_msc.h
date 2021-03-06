/******************************************************************************
** 
**  $Id: p11x_msc.h,v 1.2 2005/03/15 17:40:02 ko189283 Exp $
**
**  Package: PKCS-11
**  Author : Chris Osgood <oznet@mac.com>
**  License: Copyright (C) 2002 Schlumberger Network Solutions
**           <http://www.slb.com/sns>
**  Purpose: MSC wrappers
** 
******************************************************************************/

MSC_RV msc_Initialize();

void msc_Finalize();

MSC_RV msc_ListTokens(
  MSCULong32            listScope,        /* defines the scope to return */
  MSCLPTokenInfo        tokenArray,       /* token struct array          */
  MSCPULong32           arrayLength       /* Length of array             */
);

MSC_RV msc_EstablishConnection( 
  MSCLPTokenInfo        tokenStruct,       /* The struct of token   */
  MSCULong32            sharingMode,       /* Mode of sharing       */
  MSCPUChar8            applicationName,   /* The applet ID/Name    */
  MSCULong32            nameSize,          /* The ID/Name Size      */
  MSCLPTokenConnection  pConnection        /* Returned connection   */
);

MSC_RV msc_ReleaseConnection( 
  MSCLPTokenConnection  pConnection,       /* Connection handle     */
  MSCULong32            endAction          /* Action to perform     */
);

MSC_RV msc_WaitForTokenEvent( 
  MSCLPTokenInfo        tokenArray,        /* Array of token structs */
  MSCULong32            arraySize,	   /* Size of the array      */
  MSCULong32            timeoutValue       /* Timeout                */
);

MSC_RV msc_CancelEventWait( 
  void                                     /* No parameters          */
);

MSC_RV msc_CallbackForTokenEvent(
  MSCLPTokenInfo        tokenArray,        /* Array of token structs */
  MSCULong32            arraySize,         /* Size of the array      */
  MSCCallBack           callBack,          /* Callback function      */
  MSCPVoid32            appData            /* Application data       */
);

MSC_RV msc_CallbackCancelEvent();

MSC_RV msc_BeginTransaction(
  MSCLPTokenConnection  pConnection       /* Connection handle          */
);

MSC_RV msc_EndTransaction(
  MSCLPTokenConnection  pConnection,      /* Connection handle          */
  MSCULong32            endAction         /* Action to perform on token */
);

MSC_RV msc_WriteFramework( 
  MSCLPTokenConnection  pConnection, 
  MSCLPInitTokenParams  pInitParams 
);

/** Matheus: changed to reflect new MSC prototype */
//MSC_RV msc_GetStatus(
//  MSCLPTokenConnection  pConnection, 
//  MSCLPStatusInfo       pStatusInfo
//);
MSC_RV msc_GetStatus(
	MSCLPTokenConnection pConnection,
	MSCULong32 Tag, 
	MSCPUChar8 Value, 
	MSCPULong32 Length
);
		

MSC_RV msc_GetCapabilities(
  MSCLPTokenConnection  pConnection,
  MSCULong32            Tag,
  MSCPUChar8            Value,
  MSCPULong32           Length
);

MSC_RV msc_ExtendedFeature( 
  MSCLPTokenConnection  pConnection, 
  MSCULong32            extFeature,
  MSCPUChar8            outData, 
  MSCULong32            outLength, 
  MSCPUChar8            inData,
  MSCPULong32           inLength 
);

MSC_RV msc_GenerateKeys(
  MSCLPTokenConnection	pConnection,
  MSCUChar8		prvKeyNum,
  MSCUChar8		pubKeyNum,
  MSCLPGenKeyParams	pParams
);

/** Matheus: changed to reflect new prototype */
/*MSC_RV msc_ImportKey(
  MSCLPTokenConnection	pConnection,
  MSCUChar8		keyNum,
  MSCLPKeyACL		pKeyACL,
  MSCPUChar8	        pKeyBlob,
  MSCULong32            keyBlobSize,
  MSCLPKeyPolicy        keyPolicy,
  MSCPVoid32		pAddParams,
  MSCUChar8		addParamsSize
  ); */
MSC_RV msc_ImportKey(
	MSCLPTokenConnection pConnection,
	MSCUChar8 keyNum,
	MSCLPKeyACL pKeyACL,
	MSCPUChar8 pKeyBlob,
	MSCULong32 keyBlobSize,
	MSCLPKeyPolicy pKeyPolicy,
	MSCUShort16 keyFlags,
//	MSCUChar8 keyPartner,
	MSCPVoid32 pAddParams, MSCUChar8 addParamsSize
);

MSC_RV msc_ExportKey(
  MSCLPTokenConnection	pConnection,
  MSCUChar8		keyNum,
  MSCPUChar8	        pKeyBlob,
  MSCPULong32           keyBlobSize,
  MSCPVoid32		pAddParams,
  MSCUChar8		addParamsSize
);

MSC_RV msc_ComputeCrypt( 
  P11_Slot*             slot,
  CK_ULONG              slotID,
  MSCLPTokenConnection  pConnection,
  MSCLPCryptInit        cryptInit, 
  MSCPUChar8            pInputData,
  MSCULong32            inputDataSize, 
  MSCPUChar8            pOutputData,
  MSCPULong32           outputDataSize
);


MSC_RV msc_ExtAuthenticate(
  MSCLPTokenConnection	pConnection,
  MSCUChar8	        keyNum,
  MSCUChar8             cipherMode, 
  MSCUChar8             cipherDirection,
  MSCPUChar8	        pData,
  MSCULong32	        dataSize
);


MSC_RV msc_ListKeys(
  MSCLPTokenConnection	pConnection,
  MSCUChar8		seqOption,
  MSCLPKeyInfo		pKeyInfo
);

MSC_RV msc_CreatePIN(
  MSCLPTokenConnection	pConnection,
  MSCUChar8		        pinNum,
  MSCPUChar8	        pPinCode,
  MSCULong32		    pinCodeSize,
  MSCPUChar8	        pUnblockCode,
  MSCUChar8		        unblockCodeSize
);

/* jvictor */
MSC_RV msc_VerifyPUK(
  MSCLPTokenConnection	pConnection,
  MSCUChar8				pukNum,
  MSCPUChar8	        pPukCode,
  MSCULong32			pukCodeSize
);

MSC_RV msc_VerifyPIN(
  MSCLPTokenConnection	pConnection,
  MSCUChar8		pinNum,
  MSCPUChar8	        pPinCode,
  MSCULong32		pinCodeSize
);


/* jvictor */
MSC_RV msc_ChangePUK(
  MSCLPTokenConnection	pConnection,
  MSCUChar8		pukNum,
  MSCPUChar8	        pOldPukCode,
  MSCUChar8		oldPukCodeSize,
  MSCPUChar8	        pNewPukCode,
  MSCUChar8		newPukCodeSize
);

/* jvictor */
MSC_RV msc_Reset(
  MSCLPTokenConnection	pConnection,
  MSCUChar8			    pinNum,
  MSCPUChar8	        pDataLabel
);


MSC_RV msc_ChangePIN(
  MSCLPTokenConnection	pConnection,
  MSCUChar8		pinNum,
  MSCPUChar8	        pOldPinCode,
  MSCUChar8		oldPinCodeSize,
  MSCPUChar8	        pNewPinCode,
  MSCUChar8		newPinCodeSize
);

/** Matheus: changed to reflect new prototype */
/*MSC_RV msc_UnblockPIN(
  MSCLPTokenConnection	pConnection,
  MSCUChar8		pinNum,
  MSCPUChar8	        pUnblockCode,
  MSCULong32		unblockCodeSize
);*/
MSC_RV msc_UnblockPIN(
	MSCLPTokenConnection pConnection,
	MSCUChar8 PINNum,
	MSCPUChar8 pUnblockCode, 
	MSCULong32 unblockCodeSize
);



MSC_RV msc_ListPINs(
  MSCLPTokenConnection	pConnection,
  MSCPUShort16	        pPinBitMask
);


MSC_RV msc_CreateObject(
  MSCLPTokenConnection	pConnection,
  MSCString 	        objectID,
  MSCULong32		objectSize,
  MSCLPObjectACL	pObjectACL
);


MSC_RV msc_DeleteObject(
  MSCLPTokenConnection	pConnection,
  MSCString  		objectID
);


MSC_RV msc_WriteObject(
  MSCLPTokenConnection	pConnection,
  MSCString 		objectID,
  MSCULong32		offset,
  MSCPUChar8	        pInputData,
  MSCULong32		dataSize
);


MSC_RV msc_ReadObject(
  MSCLPTokenConnection	pConnection,
  MSCString 		objectID,
  MSCULong32		offset,
  MSCPUChar8	        pOutputData,
  MSCULong32		dataSize
);


MSC_RV msc_ListObjects(
  MSCLPTokenConnection	pConnection,
  MSCUChar8		seqOption,
  MSCLPObjectInfo	pObjectInfo
);


MSC_RV msc_LogoutAll(
  MSCLPTokenConnection	pConnection
);


MSC_RV msc_GetChallenge(
  MSCLPTokenConnection	pConnection,
  MSCPUChar8	        pSeed,
  MSCUShort16	        seedSize,
  MSCPUChar8	        pRandomData,
  MSCUShort16	        randomDataSize
);


MSC_RV msc_GetKeyAttributes( 
  MSCLPTokenConnection  pConnection, 
  MSCUChar8             keyNumber,
  MSCLPKeyInfo          pKeyInfo 
);


MSC_RV msc_GetObjectAttributes( 
  MSCLPTokenConnection  pConnection, 
  MSCString             objectID,
  MSCLPObjectInfo       pObjectInfo 
);


MSC_RV msc_ReadAllocateObject( 
  MSCLPTokenConnection  pConnection, 
  MSCString             objectID,
  MSCPUChar8*           pOutputData, 
  MSCPULong32           dataSize 
);

MSCUChar8 msc_IsTokenReset(MSCLPTokenConnection pConnection);
MSCUChar8 msc_ClearReset(MSCLPTokenConnection pConnection);
MSCUChar8 msc_IsTokenMoved(MSCLPTokenConnection pConnection);
MSCUChar8 msc_IsTokenChanged(MSCLPTokenConnection pConnection);
MSCUChar8 msc_IsTokenKnown(MSCLPTokenConnection pConnection);
