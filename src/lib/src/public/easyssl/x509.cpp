//#
//# Copyright (C) 2021-2023 QuasarApp.
//# Distributed under the GPLv3 software license, see the accompanying
//# Everyone is permitted to copy and distribute verbatim copies
//# of this license document, but changing it is not allowed.
//#

#include "x509.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <easysslutils.h>
namespace EasySSL {

X509::X509(const QSharedPointer<ICrypto>& generator): ICertificate(generator) {

}

SelfSignedSertificate X509::create(const SslSrtData &certificateData) const {
    SelfSignedSertificate result;
    if (!(keyGenerator()->supportedFeatures() & ICrypto::Features::Signing)) {
        return {};
    }

    EVP_PKEY *pkey = keyGenerator()->makeRawKeys();

    ::X509 * x509 = nullptr;
    X509_NAME * name = nullptr;

    x509 = X509_new();
    q_check_ptr(x509);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0); // not before current time
    X509_gmtime_adj(X509_get_notAfter(x509), certificateData.endTime); // not after a year from this point
    X509_set_pubkey(x509, pkey);
    name = X509_get_subject_name(x509);
    q_check_ptr(name);

    unsigned char *C = reinterpret_cast<unsigned char *>(certificateData.country.toLatin1().data());
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, C, -1, -1, 0);

    unsigned char *O = reinterpret_cast<unsigned char *>(certificateData.organization.toLatin1().data());
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, O, -1, -1, 0);

    unsigned char *CN = reinterpret_cast<unsigned char *>(certificateData.commonName.toLatin1().data());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, CN, -1, -1, 0);

    X509_set_issuer_name(x509, name);
    X509_sign(x509, pkey, EVP_sha256());

    result.key = QSslKey(EasySSLUtils::extractPrivateKey(pkey), keyGenerator()->keyAlgorithm());
    if(result.key.isNull()) {
        EVP_PKEY_free(pkey);
        X509_free(x509);
        BIO_free_all(bp_public);
        BIO_free_all(bp_private);
        qCritical("Failed to generate a random private key");
        return {};
    }
    EVP_PKEY_free(pkey);
    BIO_free_all(bp_private);

    BIO * bp_public = BIO_new(BIO_s_mem());
    q_check_ptr(bp_public);
    if(PEM_write_bio_X509(bp_public, x509) != 1){
        X509_free(x509);
        BIO_free_all(bp_public);
        qCritical("PEM_write_bio_PrivateKey");
        return {};
    }

    result.crt = QSslCertificate(EasySSLUtils::bioToByteArray(bp_public));
    if(result.crt.isNull()) {
        X509_free(x509);
        BIO_free_all(bp_public);
        qCritical("Failed to generate a random client certificate");
        return {};
    }

    X509_free(x509);
    BIO_free_all(bp_public);

    return result;
}

}
