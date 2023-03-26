//#
//# Copyright (C) 2021-2023 QuasarApp.
//# Distributed under the GPLv3 software license, see the accompanying
//# Everyone is permitted to copy and distribute verbatim copies
//# of this license document, but changing it is not allowed.
//#


#include "ecdsassl11.h"

#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp192k1
#include <openssl/evp.h>
#include <openssl/err.h>

#include <QCryptographicHash>
#include <QDataStream>
#include <QIODevice>
#include <QVector>

namespace EasySSL {

void printlastOpenSSlError() {
    int error = ERR_get_error();
    char buffer[256];
    ERR_error_string(error, buffer);
}

bool prepareKeyAdnGroupObjects(EC_KEY **eckey, EC_GROUP **ecgroup) {

    // input data should be valid pointers to pointers of key and group objects.
    if (!(eckey && ecgroup))
        return false;

    // input pointers should be nullptr;
    if ((*eckey) || (*ecgroup))
        return false;

    auto free = [eckey, ecgroup] () {
        if (*ecgroup)
            EC_GROUP_free(*ecgroup);

        if (*eckey)
            EC_KEY_free(*eckey);
    };

    *eckey = EC_KEY_new();
    if (!*eckey) {
        printlastOpenSSlError();
        free();
        return false;
    }

    *ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);

    if (!*ecgroup) {
        printlastOpenSSlError();
        free();
        return false;
    }

    if (!EC_KEY_set_group(*eckey, *ecgroup)) {
        printlastOpenSSlError();
        free();
        return false;
    }

    return true;
}


ECDSASSL11::ECDSASSL11() {

}

QByteArray bignumToArray(const BIGNUM* num) {
    int length = BN_bn2mpi(num, nullptr);
    QVector<unsigned char> data(length);
    BN_bn2mpi(num, data.data());
    QByteArray result;
    result.insert(0, reinterpret_cast<char*>(data.data()), data.length());
    return result;
}

BIGNUM* bignumFromArray(const QByteArray& array) {
    auto d = reinterpret_cast<const unsigned char*>(array.data());
    BIGNUM* result = BN_mpi2bn(d,
                               array.length(), nullptr);
    if (!result) {
        printlastOpenSSlError();
    }

    return result;
}

QByteArray extractPrivateKey(EC_KEY* ec_key) {
    const BIGNUM* ec_priv = EC_KEY_get0_private_key(ec_key);
    return bignumToArray(ec_priv);
}

QByteArray extractPublicKey(EC_KEY* key, EC_GROUP* group) {

    QByteArray data;
    point_conversion_form_t form = EC_GROUP_get_point_conversion_form(group);

    unsigned char* pub_key_buffer;
    size_t length = EC_KEY_key2buf(key, form, &pub_key_buffer, nullptr);

    if (length <= 0) {
        printlastOpenSSlError();
        return {};
    }

    data.insert(0, reinterpret_cast<const char*>(pub_key_buffer), length);

    OPENSSL_free(pub_key_buffer);

    return data;
}

bool ECDSASSL11::makeKeys(QByteArray &pubKey, QByteArray &privKey) const {

    EC_KEY *eckey= nullptr;
    EC_GROUP *ecgroup = nullptr;

    if (!prepareKeyAdnGroupObjects(&eckey, &ecgroup)) {
        return false;
    }

    if (!EC_KEY_generate_key(eckey)) {
        printlastOpenSSlError();
        EC_GROUP_free(ecgroup);
        EC_KEY_free(eckey);
        return false;
    }

    pubKey = extractPublicKey(eckey, ecgroup);
    privKey = extractPrivateKey(eckey);

    return pubKey.length() && privKey.length();
}

ICrypto::Features ECDSASSL11::supportedFeatures() const {
    return Features::Signing;
}

QByteArray ECDSASSL11::signMessage(const QByteArray &inputData,
                                  const QByteArray &key) const {

    EC_KEY *eckey= nullptr;
    EC_GROUP *ecgroup = nullptr;

    if (!prepareKeyAdnGroupObjects(&eckey, &ecgroup)) {
        return {};
    }

    auto hash = QCryptographicHash::hash(inputData,
                                         QCryptographicHash::Sha256);

    BIGNUM* priv = bignumFromArray(key);
    if (!EC_KEY_set_private_key(eckey, priv)) {
        printlastOpenSSlError();
        EC_GROUP_free(ecgroup);
        EC_KEY_free(eckey);
        return {};
    };

    ECDSA_SIG *signature = ECDSA_do_sign(reinterpret_cast<const unsigned char*>(hash.data()),
                                         hash.length(), eckey);
    BN_free(priv);
    EC_KEY_free(eckey);
    EC_GROUP_free(ecgroup);

    if (!signature) {
        printlastOpenSSlError();
        return {};
    }

    const BIGNUM * R, *S;
    ECDSA_SIG_get0(signature, &R, &S);

    QByteArray result;
    QDataStream stream(&result, QIODevice::WriteOnly);

    stream << bignumToArray(R);
    stream << bignumToArray(S);

    ECDSA_SIG_free(signature);

    return result;
}

bool ECDSASSL11::checkSign(const QByteArray &inputData,
                          const QByteArray &signature,
                          const QByteArray &key) const {


    // extract signature from raw array

    BIGNUM * R, *S;
    QDataStream stream(signature);

    QByteArray rR,rS;
    stream >> rR;
    stream >> rS;
    R = bignumFromArray(rR);
    S = bignumFromArray(rS);

    ECDSA_SIG *sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(sig, R, S);

    auto hash = QCryptographicHash::hash(inputData,
                                         QCryptographicHash::Sha256);


    EC_KEY *eckey= nullptr;
    EC_GROUP *ecgroup = nullptr;

    if (!prepareKeyAdnGroupObjects(&eckey, &ecgroup)) {
        ECDSA_SIG_free(sig);
        return {};
    }


    // extract key from raw array;
    EC_POINT* ec_point = EC_POINT_new(ecgroup);
    EC_POINT_oct2point(ecgroup, ec_point,
                       reinterpret_cast<const unsigned char*>(key.data()),
                       key.length(), nullptr);

    EC_KEY_set_public_key(eckey, ec_point);


    int verify_status = ECDSA_do_verify(reinterpret_cast<const unsigned char*>(hash.data()),
                                        hash.length(), sig, eckey);

    ECDSA_SIG_free(sig);
    EC_POINT_free(ec_point);

    return verify_status == 1;

}

QByteArray ECDSASSL11::decrypt(const QByteArray &, const QByteArray &) {
    return {};
}

QByteArray ECDSASSL11::encrypt(const QByteArray &, const QByteArray &) {
    return {};
}

}
