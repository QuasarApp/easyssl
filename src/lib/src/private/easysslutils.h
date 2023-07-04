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
 * @brief The EasySSLUtils class This is base utils for work with opwnssl library.
 */
class EasySSLUtils {

public:

    /**
     * @brief printlastOpenSSlError This method print last ssl error message.
     */
    static void printlastOpenSSlError();

    /**
     * @brief bignumToArray This method convert openssl BIGNUM into byteArray
     * @param num This is big num of the openssl  library
     * @return bytes array.
     */
    static QByteArray bignumToArray(const BIGNUM* num);

    /**
     * @brief bignumFromArray This method convert Qt bytes array into opensll big num.
     * @param array This is input array.
     * @return big num pointer.
     * @note This result pointer will not free automatically. Please free returned pointer after using.
     */
    [[nodiscard("This pointer will not free automatically. Please free returned pointer after using.")]]
    static BIGNUM* bignumFromArray(const QByteArray& array);
};



};
