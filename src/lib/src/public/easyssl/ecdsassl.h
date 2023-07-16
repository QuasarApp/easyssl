//#
//# Copyright (C) 2021-2023 QuasarApp.
//# Distributed under the GPLv3 software license, see the accompanying
//# Everyone is permitted to copy and distribute verbatim copies
//# of this license document, but changing it is not allowed.
//#


#ifndef QH_ECDSA_SSL_1_1_H
#define QH_ECDSA_SSL_1_1_H

#include "global.h"
#include "icrypto.h"

namespace EasySSL {

/**
 * @brief The ECDSASSL11 class is ecdsa implementation of the Async authentication. This implementation based on Openssl library.
 */
class EASYSSL_EXPORT ECDSASSL: public EasySSL::ICrypto
{
    /**
     * @brief The EllipticCurveStandart enum List of supported Elliptic Curve Standarts
     */
    enum EllipticCurveStandart {
        /// Private key (point on Elliptic Curve ) based on 256 bit prime number
        P_256,
        /// Private key (point on Elliptic Curve ) based on 384 bit prime number
        P_384,
        /// Private key (point on Elliptic Curve ) based on 521 bit prime number
        P_521,
        /// based on elliptic curve potentially offering 224 bits of security and designed for use with the elliptic-curve Diffie–Hellman (ECDH) key agreement scheme
        X448,
        ///  base on an elliptic curve used in elliptic-curve cryptography (ECC) offering 128 bits of security (256-bit key size) and designed for use with the elliptic curve Diffie–Hellman (ECDH) key agreement scheme. It is one of the fastest curves in ECC, and is not covered by any known patents.
        X25519
    };

public:
    ECDSASSL(EllipticCurveStandart curveStandart = EllipticCurveStandart::P_256);
    EVP_PKEY * makeRawKeys() const override;
    Features supportedFeatures() const override;
    QSsl::KeyAlgorithm keyAlgorithm() const override;

    QByteArray signMessage(const QByteArray &inputData, const QByteArray &key) const override;
    bool checkSign(const QByteArray &inputData, const QByteArray &signature, const QByteArray &key) const override;

    /**
     * @brief decrypt This method has empty implementation.
     * @return empty array.
     */
    QByteArray decrypt(const QByteArray &message, const QByteArray &key) override;

    /**
     * @brief encrypt This method has empty implementation.
     * @return empty array.
     */
    QByteArray encrypt(const QByteArray &message, const QByteArray &key) override;

    /**
     * @brief curve This method return current curve method. using only for generate new pair keys.
     * @return current cursve type.
     * @see EllipticCurveStandart
     */
    EllipticCurveStandart curve() const;

    /**
     * @brief setCurve This method sets new curve standart value.
     * @param newCurve this is new value of curve standart.
     */
    void setCurve(EllipticCurveStandart newCurve);

private:
    const char *getCStr(EllipticCurveStandart value) const;
    EllipticCurveStandart _curve = EllipticCurveStandart::P_256;
};

}

#endif // QH_ECDSA_SSL_1_1_H
