//#
//# Copyright (C) 2021-2023 QuasarApp.
//# Distributed under the GPLv3 software license, see the accompanying
//# Everyone is permitted to copy and distribute verbatim copies
//# of this license document, but changing it is not allowed.
//#


#include "rsassl.h"
#include "qcryptographichash.h"
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <easysslutils.h>
#include <QDebug>

namespace EasySSL {

RSASSL::RSASSL(RSAPadding padding) {
    setPadding(padding);
}

void *RSASSL::makeRawKeys() const {

    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_CTX *pctx =  EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    EVP_PKEY_keygen_init(pctx);

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, _bits) <= 0) {
        EasySSLUtils::printlastOpenSSlError();
    };

    EVP_PKEY_generate(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);

    return pkey;
}

ICrypto::Features RSASSL::supportedFeatures() const {
    return static_cast<ICrypto::Features>(Features::Encription | Features::Signing);
}

QSsl::KeyAlgorithm RSASSL::keyAlgorithm() const {
    return QSsl::KeyAlgorithm::Rsa;
}

QByteArray RSASSL::signMessage(const QByteArray &inputData, const QByteArray &key) const {
    QByteArray signature;

    auto pkey = EasySSLUtils::byteArrayToBio(key);
    auto rsaPrivateKey = PEM_read_bio_PrivateKey(pkey, nullptr, nullptr, nullptr);
    BIO_free(pkey);

    if (!rsaPrivateKey) {
        qCritical() << "Error reading private key";
        EasySSLUtils::printlastOpenSSlError();
        return {};
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        return {};
    }

    // Initialize the signing operation
    if (EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, rsaPrivateKey) != 1) {
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

    size_t signatureLength = EVP_PKEY_size(rsaPrivateKey);
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

bool RSASSL::checkSign(const QByteArray &inputData, const QByteArray &signature, const QByteArray &key) const {
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

QByteArray RSASSL::decrypt(const QByteArray &message, const QByteArray &key) {

    auto pkey = EasySSLUtils::byteArrayToBio(key);
    auto rsaPrivateKey = PEM_read_bio_PrivateKey(pkey, nullptr, nullptr, nullptr);
    BIO_free(pkey);

    if (!rsaPrivateKey) {        
        qCritical() << "Error reading private key";
        EasySSLUtils::printlastOpenSSlError();
        return {};
    }

    const long long maxDencryptedSize = EVP_PKEY_size(rsaPrivateKey);
    if (message.length() % maxDencryptedSize) {
        qCritical() << "Error wrong encripted data size.";
        qCritical() << "Your key requir size multiple " << maxDencryptedSize;

        return {};
    }


    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(rsaPrivateKey, nullptr);
    if (ctx == nullptr) {
        EVP_PKEY_free(rsaPrivateKey);
        return {};
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EasySSLUtils::printlastOpenSSlError();

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(rsaPrivateKey);        
        return {};
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, getRawOpenSSLPandingValue(_padding)) <= 0) {
        EasySSLUtils::printlastOpenSSlError();
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(rsaPrivateKey);
        return {};
    }

    QByteArray decryptedData;

    for (int index = 0; index < message.size(); index += maxDencryptedSize) {

        QByteArray decryptedDataPart(maxDencryptedSize, 0);
        size_t realDecryptedDataPartSize = maxDencryptedSize; // must be equals or large of private key size.
        if (EVP_PKEY_decrypt(ctx,
                             reinterpret_cast<unsigned char*>(decryptedDataPart.data()),
                             &realDecryptedDataPartSize,
                             reinterpret_cast<const unsigned char*>(&(message.constData()[index])),
                             maxDencryptedSize) <= 0) {

            EasySSLUtils::printlastOpenSSlError();
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(rsaPrivateKey);
            return {};
        }

        decryptedData += decryptedDataPart.left(realDecryptedDataPartSize);
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(rsaPrivateKey);
    return decryptedData;

}

QByteArray RSASSL::encrypt(const QByteArray &message, const QByteArray &key) {
    auto pkey = EasySSLUtils::byteArrayToBio(key);
    auto rsaPublicKey = PEM_read_bio_PUBKEY(pkey, nullptr, nullptr, nullptr);
    BIO_free(pkey);

    if (!rsaPublicKey) {
        qCritical() << "Error reading public key";
        EasySSLUtils::printlastOpenSSlError();
        return {};
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(rsaPublicKey, nullptr);
    if (ctx == nullptr) {
        EasySSLUtils::printlastOpenSSlError();
        EVP_PKEY_free(rsaPublicKey);
        return {};
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EasySSLUtils::printlastOpenSSlError();
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(rsaPublicKey);
        return {};
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, getRawOpenSSLPandingValue(_padding)) <= 0) {
        EasySSLUtils::printlastOpenSSlError();
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(rsaPublicKey);
        return {};
    }

    const long long maxEncryptedSize = EVP_PKEY_size(rsaPublicKey);
    QByteArray encryptedData;

    for (int index = 0; index < message.size();) {

        QByteArray encryptedDataPart(maxEncryptedSize, 0);
        size_t realEncryptedDataPartSize = 0;
        int currentPartSize = std::min(message.length() - index, maxEncryptedSize - getPandingSize(_padding)) ;
        if (EVP_PKEY_encrypt(ctx,
                             reinterpret_cast<unsigned char*>(encryptedDataPart.data()),
                             &realEncryptedDataPartSize,
                             reinterpret_cast<const unsigned char*>(&(message.constData()[index])),
                             currentPartSize) <= 0) {

            EasySSLUtils::printlastOpenSSlError();
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(rsaPublicKey);
            return {};
        }

        encryptedData += encryptedDataPart.left(realEncryptedDataPartSize);
        index += currentPartSize;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(rsaPublicKey);
    return encryptedData;
}

RSASSL::RSAPadding RSASSL::padding() const {
    return _padding;
}

void RSASSL::setPadding(RSAPadding newPadding) {
    _padding = newPadding;
}

int RSASSL::getRawOpenSSLPandingValue(RSAPadding panding) {
    switch (panding) {
    case NO_PADDING: return RSA_NO_PADDING;
    case PKCS1_OAEP_PADDING: return RSA_PKCS1_OAEP_PADDING;
    case PKCS1_PADDING: return RSA_PKCS1_PADDING;

    default:
        return 0;
    }
}

int RSASSL::getPandingSize(RSAPadding panding) {
    switch (panding) {
    case PKCS1_OAEP_PADDING: return 42;
    case PKCS1_PADDING: return 11;

    default:
        return 0;
    }
}

RSASSL::RSABits RSASSL::bits() const {
    return _bits;
}

void RSASSL::setBits(RSABits newBits) {
    _bits = newBits;
}

}
