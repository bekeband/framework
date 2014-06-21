
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "crypto/rsa.h"
#include "ret_codes.h"
#include "rsa_enc_dec.h"

#include "crypto/src/drv_common.h"
#include "crypto/src/sys_common.h"

typedef struct
{
    uint8_t * xBuffer;
    uint8_t * yBuffer;
    uint16_t xLen;
    uint16_t yLen;
    uint32_t length;
    uint32_t * msgSize;
    DRV_RSA_RandomGet randFunc;
    DRV_RSA_PAD_TYPE padType;
    DRV_IO_INTENT runType;
    DRV_RSA_STATUS status;
    DRV_RSA_OPERATION_MODES op;
} DRV_RSA_DESC;

static DRV_RSA_DESC rsaDesc0;

__inline static bool is_aligned (void *p)
{
    return (int)p % 2 == 0;
}

SYS_MODULE_OBJ DRV_RSA_Initialize( const SYS_MODULE_INDEX index, const SYS_MODULE_INIT * const init)
{
    if (index != DRV_RSA_INDEX)
    {
        return SYS_MODULE_OBJ_INVALID;
    }

    rsaDesc0.xBuffer = NULL;
    rsaDesc0.xLen = 0;
    rsaDesc0.yBuffer = NULL;
    rsaDesc0.yLen = 0;
    rsaDesc0.randFunc = NULL;
    rsaDesc0.padType = DRV_RSA_PAD_DEFAULT;
    rsaDesc0.runType = DRV_IO_INTENT_EXCLUSIVE;
    rsaDesc0.status = DRV_RSA_STATUS_INIT;
    rsaDesc0.op = DRV_RSA_OPERATION_MODE_NONE;

    return SYS_MODULE_OBJ_STATIC;
}

void DRV_RSA_Deinitialize( SYS_MODULE_OBJ object)
{
    rsaDesc0.xBuffer = NULL;
    rsaDesc0.xLen = 0;
    rsaDesc0.yBuffer = NULL;
    rsaDesc0.yLen = 0;
    rsaDesc0.randFunc = NULL;
    rsaDesc0.padType = DRV_RSA_PAD_DEFAULT;
    rsaDesc0.runType = DRV_IO_INTENT_EXCLUSIVE;
    rsaDesc0.status = DRV_RSA_STATUS_INVALID;
    rsaDesc0.op = DRV_RSA_OPERATION_MODE_NONE;

    return;
}

DRV_HANDLE DRV_RSA_Open( const SYS_MODULE_INDEX index, const DRV_IO_INTENT ioIntent)
{
    if (index != DRV_RSA_INDEX)
    {
        return DRV_HANDLE_INVALID;
    }
    if (rsaDesc0.status != DRV_RSA_STATUS_INIT)
    {
        return DRV_HANDLE_INVALID;
    }
    
    rsaDesc0.runType = (ioIntent | DRV_IO_INTENT_EXCLUSIVE);

    rsaDesc0.status = DRV_RSA_STATUS_OPEN;

    return DRV_RSA_HANDLE;
}

void DRV_RSA_Close (DRV_HANDLE handle)
{
    rsaDesc0.xBuffer = NULL;
    rsaDesc0.xLen = 0;
    rsaDesc0.yBuffer = NULL;
    rsaDesc0.yLen = 0;
    rsaDesc0.randFunc = NULL;
    rsaDesc0.padType = DRV_RSA_PAD_DEFAULT;
    rsaDesc0.runType = DRV_IO_INTENT_EXCLUSIVE;
    rsaDesc0.status = DRV_RSA_STATUS_INIT;
    rsaDesc0.op = DRV_RSA_OPERATION_MODE_NONE;

    return;
}

DRV_RSA_STATUS DRV_RSA_ClientStatus( DRV_HANDLE handle )
{
    return rsaDesc0.status;
}

int DRV_RSA_Configure(DRV_HANDLE h, uint8_t *xBuffer, uint8_t *yBuffer, uint16_t xLen, uint16_t yLen,  DRV_RSA_RandomGet randFunc, DRV_RSA_PAD_TYPE padType)
{
    if (h != DRV_RSA_HANDLE || (padType != DRV_RSA_PAD_DEFAULT && padType != DRV_RSA_PAD_PKCS1))
    {
        return -1;
    }

    if (xBuffer == NULL || yBuffer == NULL || randFunc == NULL)
    {
        return -1;
    }

    if (xLen == 0 || yLen == 0)
    {
        return -1;
    }

    if (!is_aligned (xBuffer) || !is_aligned(yBuffer))
    {
        return -1;
    }

    rsaDesc0.xBuffer = xBuffer;
    rsaDesc0.xLen = xLen;
    rsaDesc0.yBuffer = yBuffer;
    rsaDesc0.yLen = yLen;
    rsaDesc0.randFunc = randFunc;
    rsaDesc0.padType = padType;
    rsaDesc0.status = DRV_RSA_STATUS_READY;

    return 0;
}

DRV_RSA_STATUS DRV_RSA_Encrypt (DRV_HANDLE handle, uint8_t *cipherText, uint8_t *plainText, uint16_t msgLen, const DRV_RSA_PUBLIC_KEY *publicKey)
{
    uint16_t retVal;

    retVal = rsa_encrypt (cipherText, plainText, msgLen, publicKey->n, publicKey->nLen, publicKey->exp, publicKey->eLen, rsaDesc0.xBuffer, rsaDesc0.yBuffer, rsaDesc0.randFunc);

    switch (retVal)
    {
        case MCL_SUCCESS:
            return DRV_RSA_STATUS_READY;
            break;
        case MCL_ILLEGAL_PARAMETER:
            return DRV_RSA_STATUS_BAD_PARAM;
            break;
        case MCL_ILLEGAL_SIZE:
        default:
            return DRV_RSA_STATUS_ERROR;            
            break;
    }
}

DRV_RSA_STATUS DRV_RSA_Decrypt (DRV_HANDLE handle, uint8_t *plainText, uint8_t *cipherText, uint16_t * msgLen, const DRV_RSA_PRIVATE_KEY_CRT *privateKey)
{
    uint16_t retVal;

    retVal = rsa_decrypt (plainText, (unsigned short int *)msgLen, cipherText, privateKey->nLen, (unsigned char *)privateKey, rsaDesc0.xBuffer, rsaDesc0.yBuffer);

    switch (retVal)
    {
        case MCL_SUCCESS:
            return DRV_RSA_STATUS_READY;
            break;
        case MCL_ILLEGAL_PARAMETER:
            return DRV_RSA_STATUS_BAD_PARAM;
            break;
        case MCL_INVALID_CIPHERTEXT:
        case MCL_ILLEGAL_SIZE:
        default:
            return DRV_RSA_STATUS_ERROR;            
            break;
    }
}

void DRV_RSA_Tasks (SYS_MODULE_OBJ object)
{
    
}

//void _DRV_RSA_RNGAbstractor (uint8_t * workingBuffer, uint8_t * dest, uint16_t count)
//{
//    uint8_t i = 0;
//    uint32_t random = rsaDesc0.randFunc();
//
//    while (count--)
//    {
//        *dest++ = (uint8_t)((random >> (8 * i)) & 0xFF);
//
//        i++;
//        if (i == 4)
//        {
//            i = 0;
//            random = rsaDesc0.randFunc();
//        }
//    }
//    
//}


