/*
 * Copyright (C) 2021-2024 QuasarApp.
 * Distributed under the GPLv3 software license, see the accompanying
 * Everyone is permitted to copy and distribute verbatim copies
 * of this license document, but changing it is not allowed.
*/

#ifndef ASYNCKEYSAUTH_H
#define ASYNCKEYSAUTH_H

#include <QCryptographicHash>
#include <time.h>
#include <QString>
#include <easyssl/icrypto.h>


namespace EasySSL {

/**
 * @brief The AsyncKeysAuth class is temaplate class for works with authorization of a pair of asynchronous keys
 *  This class contains base implementation for the authentication using async encription. The base encription alhorithm defined on the template argument **CryptoImplementation**.
 *  You can use any crypto alhorithm.
 *
 *  ## Exampel of use:
 *
 *  @code{cpp}
 *  #include <easyssl.h>
 *
 *  using ECDSAAuth = AsyncKeysAuth<ECDSA>;
 *
 *  @endcode
 *
 *
 * ### How to it works:
 *
 * * -----
 *
 * ** Client Part **
 *
 * * Client make a pair keys (public and private) = PUB and PRIV
 * * Client get current unix time = U
 * * Client make a data for signing = S
 *      S = SHA256{U + PUB}
 * * Client make a signature SIG
 *      SIG = PRIV.signMessage(S)
 * * Client prepare a auth request for server = R:
 *      R = {U,SIG,PUB}
 * * Cleint send R to server
 *
 * * -----
 *
 * ** Server Part **
 *
 * * Server receive R from client.
 * * Server compare U time with current unix time.
 * * If the diferrence more then allowed value then server reject an auth
 * * Server make S value as a client
 * * Server check SIG value and comapre it with S value
 * * If message sign is valid then server accept an auth else reject.
 * * After accept server create new user with ID = sha256(PUB) or
 * if user alredy exits make them as a logined user.
 *
 * @tparam CryptoImplementation This is internal implementaion of base encription functions.
 * @see iCrypto class.
 *
 */

template<class CryptoImplementation>
class AsyncKeysAuth: public CryptoImplementation
{
public:
    AsyncKeysAuth() {
        //The CryptoImplementation class must be support ICrypto::Features::Signing feature
        assert(this->supportedFeatures() & ICrypto::Features::Signing);
    }

    ~AsyncKeysAuth() {

    }

    /**
     * @brief auth This method make authentication and return true if the authentication finished successful else false.
     * @brief retLoginedUserId This is logined user id in Base64UrlEncoding
     * @return true if the authentication finished successful else false.
     */
    bool auth(int allowedTimeRangeSec, QString* retLoginedUserId) const {

        int diff = time(0) - _unixTime;

        if (diff < 0) {
            return false;
        }

        if (diff >= allowedTimeRangeSec) {
            return false;
        }

        QByteArray data = _publicKey;
        data.insert(0, reinterpret_cast<const char*>(&_unixTime),
                    sizeof(_unixTime));

        bool result = checkSign(data, _signature, _publicKey);

        if (result && retLoginedUserId) {
            *retLoginedUserId = getUserId();
        }

        return result;
    }

    /**
     * @brief prepare This method will generate signature for autentication of client. Please inboke this method before send request to server.
     * @return true if signature generated sucessuful.
     */
    bool prepare() {
        _unixTime = time(0);

        QByteArray data = _publicKey;
        data.insert(0, reinterpret_cast<const char*>(&_unixTime),
                    sizeof(_unixTime));

        setSignature(signMessage(data, getPrivateKey()));

        return isValid();
    }

    /**
     * @brief unixTime This method return unix time that client added for authentication.
     * @return unix time that client added for authentication.
     * @see AsyncKeysAuth::setUnixTime
     */
    unsigned int unixTime() const {
        return _unixTime;
    }

    /**
     * @brief setUnixTime This method sets new value of the unixTime propertye.
     * @param newUnixTime This is new unix time value. Unix time sets in secunds from 1970 year
     */
    void setUnixTime(unsigned int newUnixTime) {
        _unixTime = newUnixTime;
    }

    /**
     * @brief signature This method return signature array.
     * @return signature array.
     * @see AsyncKeysAuth::setSignature
     */
    const QByteArray &signature() const {
        return _signature;
    }

    /**
     * @brief isValid this method check this ibject to valid.
     * @return return true if object contains valid signature else false.
     * @note Invoke the AsyncKeysAuth::prepare method before check valid of object. All object that not be preparred is invalid.
     */
    bool isValid() const {
        return _publicKey.size() && _signature.size() && _unixTime;
    }

    /**
     * @brief getUserId This method return user id that generated from the public key.
     * @note This function works slow, because this object does not contain ID of user. The user ID will be generated every invoke of this function
     * @return user ID.
     */
    QString getUserId() const {
        return QCryptographicHash::hash(_publicKey,
                                        QCryptographicHash::Sha256).
                toBase64(QByteArray::Base64UrlEncoding);
    }


    /**
     * @brief publicKey This method return public key that client added for authentication.
     * @note The @a publicKey will be used forcreate user id.
     * @return public key that client added for authentication.
     * @see AsyncKeysAuth::setPublicKey
     */
    const QByteArray &publicKey() const {
        return _publicKey;
    }

    /**
     * @brief setPublicKey This method sets new public key for authentication.
     * @param newPublicKey Thiy is new key.
     * @see AsyncKeysAuth::publicKey
     */
    void setPublicKey(const QByteArray &newPublicKey) {
        _publicKey = newPublicKey;
    }

protected:

    QByteArray decrypt(const QByteArray &message, const QByteArray &key) override {
        return CryptoImplementation::decrypt(message, key);
    };

    QByteArray encrypt(const QByteArray &message, const QByteArray &key) override {
        return CryptoImplementation::encrypt(message, key);
    };

    QByteArray signMessage(const QByteArray &message, const QByteArray &key) const override {
        return CryptoImplementation::signMessage(message, key);
    };

    bool checkSign(const QByteArray &message, const QByteArray &signature, const QByteArray &key) const override {
        return CryptoImplementation::checkSign(message, signature, key);
    };

    /**
     * @brief getPrivateKey This method should be return private key for the public key that saved in this object.
     * @return private key for the public key that saved in this object.
     */
    virtual QByteArray getPrivateKey() const = 0;

    /**
     * @brief setSignature Tihis is internal method for sets new signature value.
     * @param newSignature new signature value.
     * @note used in the
     */
    void setSignature(const QByteArray &newSignature) {
        _signature = newSignature;
    }

    unsigned int _unixTime = 0;
    QByteArray _signature;
    QByteArray _publicKey;
};

}

#endif // ASYNCKEYSAUTH_H
