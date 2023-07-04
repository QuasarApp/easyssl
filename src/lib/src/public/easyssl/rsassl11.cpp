//#
//# Copyright (C) 2021-2023 QuasarApp.
//# Distributed under the GPLv3 software license, see the accompanying
//# Everyone is permitted to copy and distribute verbatim copies
//# of this license document, but changing it is not allowed.
//#


#include "rsassl11.h"
#include "qcryptographichash.h"
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

namespace EasySSL {

RSASSL11::RSASSL11() {

}

bool RSASSL11::makeKeys(QByteArray &pubKey, QByteArray &privKey) const {
    EVP_PKEY *pkey = EVP_PKEY_new();

    if (!pkey) {
        return false;
    }

    BIGNUM * bn = BN_new();

    int rc = BN_set_word(bn, RSA_F4);

    if (rc != 1) {
        BN_free(bn);
        EVP_PKEY_free(pkey);
        return false;
    }

    RSA * rsa = RSA_new();

    auto failed = [bn, rsa, pkey] () {
        BN_free(bn);
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        return false;
    };

    if (!RSA_generate_key_ex(rsa, 4196, bn, nullptr)) {
        return failed();
    }

    q_check_ptr(rsa);
    if (EVP_PKEY_assign_RSA(pkey, rsa) <= 0) {
        return failed();
    }

    BIO *mem;
    mem = BIO_new_mem_buf(pkey, -1); //pkey is of type char*

    auto key = PEM_read_bio_PrivateKey(mem, NULL, NULL, 0);


    BIO *private_key_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(private_key_bio, rsa, NULL, NULL, 0, NULL, NULL);
    char *private_key_data;
    long private_key_size = BIO_get_mem_data(private_key_bio, &private_key_data);
    privKey = QByteArray(private_key_data, private_key_size);
    BIO_free(private_key_bio);

    BIO *public_key_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(public_key_bio, rsa);
    char *public_key_data;
    long public_key_size = BIO_get_mem_data(public_key_bio, &public_key_data);
    pubKey = QByteArray(public_key_data, public_key_size);
    BIO_free(public_key_bio);

    return true;
}

ICrypto::Features RSASSL11::supportedFeatures() const {
    return static_cast<ICrypto::Features>(Features::Encription | Features::Signing);
}

QByteArray RSASSL11::signMessage(const QByteArray &inputData, const QByteArray &key) const {
    QByteArray signature;

    BIO* privateKeyBio = BIO_new_mem_buf(key.data(), key.size());

    RSA* rsaPrivateKey = PEM_read_bio_RSAPrivateKey(privateKeyBio, nullptr, nullptr, nullptr);
    BIO_free(privateKeyBio);

    if (!rsaPrivateKey) {
        perror("Error reading private key");
        return {};
    }

    auto hash = QCryptographicHash::hash(inputData,
                                         QCryptographicHash::Sha256);

    signature.resize(RSA_size(rsaPrivateKey));
    unsigned int signatureLength = 0;
    int result = RSA_sign(NID_sha256, reinterpret_cast<const unsigned char*>(hash.data()),
                          hash.size(), reinterpret_cast<unsigned char*>(signature.data()),
                          &signatureLength, rsaPrivateKey);
    RSA_free(rsaPrivateKey);

    if (result != 1) {
        perror("Error signing message");
        return {};
    }

    signature.resize(signatureLength);
    return signature;
}

bool RSASSL11::checkSign(const QByteArray &inputData, const QByteArray &signature, const QByteArray &key) const {
    BIO* publicKeyBio = BIO_new_mem_buf(key.data(), key.size());

    RSA* rsaPublicKey = PEM_read_bio_RSA_PUBKEY(publicKeyBio, nullptr, nullptr, nullptr);
    BIO_free(publicKeyBio);

    if (!rsaPublicKey) {
        perror("Error reading public key");
        return false;
    }

    auto hash = QCryptographicHash::hash(inputData,
                                         QCryptographicHash::Sha256);

    int result = RSA_verify(NID_sha256, reinterpret_cast<const unsigned char*>(hash.data()),
                            hash.size(), reinterpret_cast<const unsigned char*>(signature.data()),
                            signature.size(), rsaPublicKey);
    RSA_free(rsaPublicKey);

    if (result != 1) {
        perror("Error verifying signature");
        return false;
    }

    return true;
}

QByteArray RSASSL11::decrypt(const QByteArray &message, const QByteArray &key) {
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

QByteArray RSASSL11::encrypt(const QByteArray &message, const QByteArray &key) {
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
