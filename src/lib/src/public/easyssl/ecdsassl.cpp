//#
//# Copyright (C) 2021-2023 QuasarApp.
//# Distributed under the GPLv3 software license, see the accompanying
//# Everyone is permitted to copy and distribute verbatim copies
//# of this license document, but changing it is not allowed.
//#


#include "ecdsassl.h"

#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp192k1
#include <openssl/evp.h>
#include <openssl/err.h>

#include <QCryptographicHash>
#include <QDataStream>
#include <QIODevice>
#include <QVector>
#include <easysslutils.h>
#include <QDebug>
#include <openssl/pem.h>

namespace EasySSL {


ECDSASSL::ECDSASSL() {}

EVP_PKEY * ECDSASSL::makeRawKeys() const {

    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_CTX *pctx =  EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!pctx) {
        qCritical() << "Error reading public key";
        return nullptr;
    }

    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_generate(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);

    return pkey;
}

ICrypto::Features ECDSASSL::supportedFeatures() const {
    return Features::Signing;
}

QSsl::KeyAlgorithm ECDSASSL::keyAlgorithm() const {
    return QSsl::KeyAlgorithm::Ec;
}

QByteArray ECDSASSL::signMessage(const QByteArray &inputData,
                                   const QByteArray &key) const {

    QByteArray signature;

    auto pkey = EasySSLUtils::byteArrayToBio(key);
    auto ecPrivateKey = PEM_read_bio_PrivateKey(pkey, nullptr, nullptr, nullptr);
    BIO_free(pkey);

    if (!ecPrivateKey) {
        qCritical() << "Error reading private key";
        return {};
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        return {};
    }

    // Initialize the signing operation
    if (EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, ecPrivateKey) != 1) {
        EVP_MD_CTX_free(mdctx);
        return {};
    }

    auto hash = QCryptographicHash::hash(inputData,
                                         QCryptographicHash::Sha256);

    // Provide the message to be signed
    if (EVP_DigestSignUpdate(mdctx, hash.data(), hash.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        return {};
    }

    size_t signatureLength = 0;
    // Determine the length of the signature
    if (EVP_DigestSignFinal(mdctx, nullptr, &signatureLength) != 1) {
        EVP_MD_CTX_free(mdctx);
        return {};
    }

    signature.resize(signatureLength);

    // Perform the final signing operation and obtain the signature
    if (EVP_DigestSignFinal(mdctx, reinterpret_cast<unsigned char*>(signature.data()), &signatureLength) != 1) {
        EVP_MD_CTX_free(mdctx);
        return {};
    }

    EVP_MD_CTX_free(mdctx);
    return signature;
}

bool ECDSASSL::checkSign(const QByteArray &inputData,
                           const QByteArray &signature,
                           const QByteArray &key) const {


    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        return false;
    }

    auto pkey = EasySSLUtils::byteArrayToBio(key);
    auto rsaPublickKey = PEM_read_bio_PUBKEY(pkey, nullptr, nullptr, nullptr);
    BIO_free(pkey);

    // Initialize the verification operation
    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, rsaPublickKey) != 1) {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    auto hash = QCryptographicHash::hash(inputData,
                                         QCryptographicHash::Sha256);

    // Provide the message to be verified
    if (EVP_DigestVerifyUpdate(mdctx, hash.data(), hash.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    // Perform the signature verification
    int verificationResult = EVP_DigestVerifyFinal(mdctx,
                                                   reinterpret_cast<const unsigned char*>(signature.data()),
                                                   signature.length());

    EVP_MD_CTX_free(mdctx);

    return verificationResult == 1;

}

QByteArray ECDSASSL::decrypt(const QByteArray &, const QByteArray &) {
    return {};
}

QByteArray ECDSASSL::encrypt(const QByteArray &, const QByteArray &) {
    return {};
}

}
