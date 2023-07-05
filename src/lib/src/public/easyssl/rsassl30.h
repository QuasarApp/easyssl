#ifndef RSASSL30_H
#define RSASSL30_H

#include "global.h"
#include "icrypto.h"

namespace EasySSL {

/**
 * @brief The RSASSL30 class This is wrapper for RSA algorithm of openssl 3.0 libraryry.
 */
class EASYSSL_EXPORT RSASSL30: public EasySSL::ICrypto
{
public:
    RSASSL30();

    bool makeKeys(QByteArray &pubKey, QByteArray &privKey) const override;
    Features supportedFeatures() const override;


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
};

}
#endif // RSASSL30_H
