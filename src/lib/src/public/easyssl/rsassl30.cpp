//#
//# Copyright (C) 2021-2023 QuasarApp.
//# Distributed under the GPLv3 software license, see the accompanying
//# Everyone is permitted to copy and distribute verbatim copies
//# of this license document, but changing it is not allowed.
//#


#include "rsassl30.h"
#include "qcryptographichash.h"
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <easysslutils.h>

namespace EasySSL {

RSASSL30::RSASSL30() {

}

bool RSASSL30::makeKeys(QByteArray &pubKey, QByteArray &privKey) const {

    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_CTX *pctx =  EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 4096);

    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_generate(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);

    if (!pkey) {
        return false;
    }

    BIO* bio = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PUBKEY(bio, pkey) != 1) {
        EVP_PKEY_free(pkey);
        return false;
    }
    pubKey = EasySSLUtils::bioToByteArray(bio);

    if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1)
    {
        EVP_PKEY_free(pkey);
        return false;
    }

    privKey = EasySSLUtils::bioToByteArray(bio);

    return true;

}

ICrypto::Features RSASSL30::supportedFeatures() const {
    return static_cast<ICrypto::Features>(Features::Encription | Features::Signing);
}

QByteArray RSASSL30::signMessage(const QByteArray &inputData, const QByteArray &key) const {
    QByteArray signature;

    auto pkey = EasySSLUtils::byteArrayToBio(key);
    auto rsaPrivateKey = PEM_read_bio_PrivateKey(pkey, nullptr, nullptr, nullptr);
    BIO_free(pkey);

    if (!rsaPrivateKey) {
        perror("Error reading private key");
        return {};
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        return {};
    }

    // Initialize the signing operation
    if (EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, rsaPrivateKey) != 1) {
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

bool RSASSL30::checkSign(const QByteArray &inputData, const QByteArray &signature, const QByteArray &key) const {
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

QByteArray RSASSL30::decrypt(const QByteArray &message, const QByteArray &key) {
    QByteArray decryptedMessage;

    BIO* privateKeyBio = BIO_new_mem_buf(key.data(), key.size());

    RSA* rsaPrivateKey = PEM_read_bio_RSAPrivateKey(privateKeyBio, nullptr, nullptr, nullptr);
    BIO_free(privateKeyBio);

    if (!rsaPrivateKey) {
        perror("Error reading private key");
        return {};
    }

    decryptedMessage.resize(RSA_size(rsaPrivateKey));
    int result = RSA_private_decrypt(message.size(),
                                     reinterpret_cast<const unsigned char*>(message.data()),
                                     reinterpret_cast<unsigned char*>(decryptedMessage.data()),
                                     rsaPrivateKey, RSA_PKCS1_PADDING);
    RSA_free(rsaPrivateKey);

    if (result == -1) {
        perror("Error decrypting ciphertext");
        return {};
    }

    return decryptedMessage;
}

QByteArray RSASSL30::encrypt(const QByteArray &message, const QByteArray &key) {
    QByteArray encryptedMessage;
    BIO* publicKeyBio = BIO_new_mem_buf(key.data(), key.size());

    RSA* rsaPublicKey = PEM_read_bio_RSA_PUBKEY(publicKeyBio, nullptr, nullptr, nullptr);
    BIO_free(publicKeyBio);

    if (!rsaPublicKey) {
        perror("Error reading public key");
        return {};
    }

    encryptedMessage.resize(RSA_size(rsaPublicKey));

    int result = RSA_public_encrypt(message.size(),
                                    reinterpret_cast<const unsigned char*>(message.data()),
                                    reinterpret_cast<unsigned char*>(encryptedMessage.data()),
                                    rsaPublicKey, RSA_PKCS1_PADDING);
    RSA_free(rsaPublicKey);

    if (result == -1) {
        perror("Error encrypting message");
        return {};
    }

    return encryptedMessage;
}

}
