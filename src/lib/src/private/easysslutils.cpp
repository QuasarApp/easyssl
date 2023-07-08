//#
//# Copyright (C) 2021-2023 QuasarApp.
//# Distributed under the GPLv3 software license, see the accompanying
//# Everyone is permitted to copy and distribute verbatim copies
//# of this license document, but changing it is not allowed.
//#

#include "easysslutils.h"
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/types.h>
#include <QVector>

namespace EasySSL {


void EasySSLUtils::printlastOpenSSlError() {
    int error = ERR_get_error();
    char buffer[256];
    ERR_error_string(error, buffer);
}

QByteArray EasySSLUtils::bignumToArray(const BIGNUM *num) {
    int length = BN_bn2mpi(num, nullptr);
    QVector<unsigned char> data(length);
    BN_bn2mpi(num, data.data());
    QByteArray result;
    result.insert(0, reinterpret_cast<char*>(data.data()), data.length());
    return result;
}

BIGNUM *EasySSLUtils::bignumFromArray(const QByteArray &array) {
    auto d = reinterpret_cast<const unsigned char*>(array.data());
    BIGNUM* result = BN_mpi2bn(d,
                               array.length(), nullptr);
    if (!result) {
        printlastOpenSSlError();
    }

    return result;
}

QByteArray EasySSLUtils::bioToByteArray(BIO* bio) {
    QByteArray byteArray;

    int dataSize = BIO_ctrl_pending(bio);
    byteArray.resize(dataSize);
    if (BIO_read(bio, byteArray.data(), dataSize) != dataSize) {
        return {};
    }

    return byteArray;
}

BIO* EasySSLUtils::byteArrayToBio(const QByteArray& byteArray) {
    BIO* bio = BIO_new_mem_buf(byteArray.constData(), byteArray.length());
    return bio;
}

QByteArray EasySSLUtils::extractPublcKey(EVP_PKEY *ssl_keys) {
    if (!ssl_keys)
        return {};

    BIO* bio = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PUBKEY(bio, ssl_keys) != 1) {
        BIO_free(bio);
        return {};
    }

    QByteArray pubKey = bioToByteArray(bio);
    BIO_free(bio);

    return pubKey;
}

QByteArray EasySSLUtils::extractPrivateKey(EVP_PKEY *ssl_keys) {
    if (!ssl_keys)
        return {};

    BIO* bio = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PrivateKey(bio, ssl_keys, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        BIO_free(bio);
        return {};
    }

    QByteArray pKey = bioToByteArray(bio);
    BIO_free(bio);

    return pKey;
}

}
