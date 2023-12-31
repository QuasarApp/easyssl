/*
 * Copyright (C) 2021-2024 QuasarApp.
 * Distributed under the GPLv3 software license, see the accompanying
 * Everyone is permitted to copy and distribute verbatim copies
 * of this license document, but changing it is not allowed.
*/

#include "icrypto.h"

#include <easysslutils.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

namespace EasySSL {

bool EasySSL::ICrypto::makeKeys(QByteArray &pubKey, QByteArray &privKey) const
{
    EVP_PKEY *keys = static_cast<EVP_PKEY *>(makeRawKeys());
    if (!keys)
        return false;

    pubKey = EasySSLUtils::extractPublcKey(keys);
    privKey = EasySSLUtils::extractPrivateKey(keys);
    return true;
}


}
