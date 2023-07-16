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
#include <openssl/core_names.h>

namespace EasySSL {


ECDSASSL::ECDSASSL(EllipticCurveStandart curveStandart) {
    setCurve(curveStandart);
}

EVP_PKEY * ECDSASSL::makeRawKeys() const {

    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_CTX *pctx =  EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!pctx) {
        EasySSLUtils::printlastOpenSSlError();
        return nullptr;
    }

    EVP_PKEY_keygen_init(pctx);
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 const_cast<char*>(getCStr(_curve)),
                                                 0);
    params[1] = OSSL_PARAM_construct_end();
    EVP_PKEY_CTX_set_params(pctx, params);

    EVP_PKEY_generate(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);

    if (!pkey) {
        EasySSLUtils::printlastOpenSSlError();
        return nullptr;
    }
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
        EasySSLUtils::printlastOpenSSlError();
        return {};
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        return {};
    }

    // Initialize the signing operation
    if (EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, ecPrivateKey) != 1) {
        EasySSLUtils::printlastOpenSSlError();

        EVP_MD_CTX_free(mdctx);
        return {};
    }

    auto hash = QCryptographicHash::hash(inputData,
                                         QCryptographicHash::Sha256);

    // Provide the message to be signed
    if (EVP_DigestSignUpdate(mdctx, hash.data(), hash.size()) != 1) {
        EasySSLUtils::printlastOpenSSlError();

        EVP_MD_CTX_free(mdctx);
        return {};
    }

    size_t signatureLength = EVP_PKEY_size(ecPrivateKey);
    signature.resize(signatureLength);

    // Perform the final signing operation and obtain the signature
    if (EVP_DigestSignFinal(mdctx, reinterpret_cast<unsigned char*>(signature.data()), &signatureLength) != 1) {
        EasySSLUtils::printlastOpenSSlError();

        EVP_MD_CTX_free(mdctx);
        return {};
    }

    signature.resize(signatureLength);

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
        EasySSLUtils::printlastOpenSSlError();

        EVP_MD_CTX_free(mdctx);
        return false;
    }

    auto hash = QCryptographicHash::hash(inputData,
                                         QCryptographicHash::Sha256);

    // Provide the message to be verified
    if (EVP_DigestVerifyUpdate(mdctx, hash.data(), hash.size()) != 1) {
        EasySSLUtils::printlastOpenSSlError();

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

ECDSASSL::EllipticCurveStandart ECDSASSL::curve() const {
    return _curve;
}

void ECDSASSL::setCurve(EllipticCurveStandart newCurve) {
    _curve = newCurve;
}

const char *ECDSASSL::getCStr(EllipticCurveStandart value) const {
    switch (value) {
    case P_256:     return "P-256";
    case P_384:     return "P-384";
    case P_521:     return "P-521";
    case X448:      return "X448";
    case X25519:    return "X25519";

    default: return nullptr;
    }
}

}
