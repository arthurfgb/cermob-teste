/******************************************************************************
**
**  $Id: crackcert.h,v 1.2 2005/03/15 17:40:02 ko189283 Exp $
**  Package: PKCS-11
**  Author : Jamie Nicolson (nicolson@netscape.com)
**  License: Copyright (C) 1994-2003 Netscape Communications Corporation
**  Purpose: DER-encoded certificate decoding 
**
******************************************************************************/
#ifndef __CRACKCERT_H
#define __CRACKCERT_H


typedef struct {
    unsigned char *data;
    unsigned int len;
} CCItem;

typedef enum {
    PR_FALSE=0,
    PR_TRUE=1
} PRBool;

typedef enum {
    SECSuccess=0,
    SECFailure=1
} SECStatus;

#ifndef NULL
#define NULL 0
#endif

int
GetCertFields(unsigned char *cert,int cert_length,
        CCItem *issuer, CCItem *serial, CCItem *derSN, CCItem *subject,
        CCItem *valid, CCItem *subjkey);

#endif
