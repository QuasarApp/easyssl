//#
//# Copyright (C) 2021-2023 QuasarApp.
//# Distributed under the GPLv3 software license, see the accompanying
//# Everyone is permitted to copy and distribute verbatim copies
//# of this license document, but changing it is not allowed.
//#

#include <openssl/types.h>

#include <QByteArray>
namespace EasySSL {

/**
 * @brief The EasySSLUtils class These are basic utils for work with the opwnssl library.
 */
class EasySSLUtils {

public:

    /**
     * @brief printlastOpenSSlError This method prints the latest ssl error message.
     */
    static void printlastOpenSSlError();

    /**
     * @brief bignumToArray This method converts openssl BIGNUM into byteArray
     * @param num This is a big num of the openssl library
     * @return bytes array.
     */
    static QByteArray bignumToArray(const BIGNUM* num);

    /**
     * @brief bignumFromArray This method converts the Qt bytes array into the opensll big num.
     * @param array This is an input array.
     * @return big num pointer.
     * @note This result pointer will not be free automatically. Please free the returned pointer after use.
     */
    [[nodiscard("The result pointer will not be free automatically. Please free the returned pointer after using.")]]
    static BIGNUM* bignumFromArray(const QByteArray& array);

    /**
     * @brief bioToByteArray This method converts the openssl BIO to the QByteArry
     * @param bio input arrary.
     * @return Qt Array
     */
    static QByteArray bioToByteArray(BIO *bio);

    /**
     * @brief byteArrayToBio This method creates the BIO struct from the Qt QByteArray object.
     * @param byteArray This is an input Qt byte array.
     * @return pointer to the BIO struct of OpenSLL library.
     * @note Don't forget to free the result pointer.
     */
    [[nodiscard("This pointer will not free automatically. Please free returned pointer after using.")]]
    static BIO *byteArrayToBio(const QByteArray &byteArray);

    /**
     * @brief extractPublcKey This method extracts the public key from the ssl (pem) structure.
     * @param ssl_keys These are objects of the ssl keys.
     * @return bytes array of the extracted key.
     */
    static QByteArray extractPublcKey(EVP_PKEY* ssl_keys);

    /**
     * @brief extractPrivateKey This method extracts the private key from the ssl (pem) structure.
     * @param ssl_keys These are objects of the ssl keys.
     * @return bytes array of the extracted key.
     */
    static QByteArray extractPrivateKey(EVP_PKEY* ssl_keys);

};



};
