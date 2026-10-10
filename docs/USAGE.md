# EasySSL Usage

This document describes how to build the EasySSL library and how to use it in your project with working examples.

EasySSL is a Qt wrapper of the OpenSSL 3.0+ library. It simplifies the working with the asymmetric cryptography:

* encryption and decryption of data (RSA),
* signing and checking the sign of data (RSA, ECDSA),
* creating of the public/private keys pairs (RSA, ECDSA),
* creating of self-signed X509 certificates,
* asynchronous authentication based on the asymmetric keys.

### Requirements

* CMake 3.19+ or qmake,
* Qt 5 or Qt 6 (Core, Network, Test modules for the tests),
* OpenSSL 3.0 or newer (or the `BUILD_WITH_OPENSSL` option, see below).

## Build and Include

### CMake

 * `cd yourRepo`
 * `git submodule add https://github.com/QuasarApp/easyssl.git` # add the repository of EasySSL into your repo like submodule
 * `git submodule update --init --recursive`
 * Include in your CMakeLists.txt file the main CMakeLists.txt file of the EasySSL library:

      ```cmake
      add_subdirectory(easyssl)
      ```

 * Link the EasySSL library to your target:

      ```cmake
      target_link_libraries(yourLib PUBLIC easyssl)
      ```

 * Rebuild your project.

### qmake

 * `cd yourRepo`
 * `git submodule add https://github.com/QuasarApp/easyssl.git` # add the repository of EasySSL into your repo like submodule
 * `git submodule update --init --recursive`
 * Include in your `.pro` file the EasySSL sources directly:

      ```qmake
      # myapp.pro

      QT       += core network

      INCLUDEPATH += $$PWD/../easyssl/src/lib/src/public

      SOURCES += \
                  ../easyssl/src/lib/src/public/easyssl.cpp \
                  ../easyssl/src/lib/src/public/easyssl/icrypto.cpp \
                  ../easyssl/src/lib/src/public/easyssl/ecdsassl.cpp \
                  ../easyssl/src/lib/src/public/easyssl/rsassl.cpp \
                  ../easyssl/src/lib/src/public/easyssl/x509.cpp \
                  ../easyssl/src/lib/src/public/easyssl/icertificate.cpp \
                  ../easyssl/src/lib/src/private/easysslutils.cpp

      DEFINES += EASYSSL_LIBRARY

      # Link the OpenSSL 3.0+ libraryes:
      LIBS += -lcrypto -lssl
      ```

 * Rebuild your project.

> **Note:** the CMake build is the recommended way. The EasySSL library has the
> `EASYSSL_STATIC_SSL` and `BUILD_WITH_OPENSSL` build options that are only
> available for the CMake build.

### Build without the system OpenSSL (BUILD_WITH_OPENSSL)

If your system (or the target device) has no OpenSSL 3.0+ library, you can build
the OpenSSL library together with the EasySSL library. Just set the
**BUILD_WITH_OPENSSL** option to true:

``` bash
cmake .. -DBUILD_WITH_OPENSSL=1
```

In this case the EasySSL project clones the OpenSSL `openssl-3.0.9` sources,
builds the static OpenSSL libraries and links them privately into the EasySSL
binary. The built OpenSSL libraries are saved in the build directory
(`build/openssl-build`), so the deployment of your application does not depend
on the system OpenSSL libraries and you will not get conflicts between
different major versions of the SSL libraries.

* Supported platforms: Linux, Android, iOS and macOS (arm/x86).
* The Windows and WASM platforms are **not** supported.
* The OpenSSL version can be changed with the `EASYSSL_OPENSSL_TAG` option
  (default `openssl-3.0.9`).

### Static SSL link (EASYSSL_STATIC_SSL)

If your system has the OpenSSL 3.0+ library but you want to avoid the runtime
dependency on it (for example the QNetwork 5.15 depends on the SSL 1.1 and
EasySSL works with the SSL >= 3.0), you can link the static OpenSSL libraries
into the EasySSL binary:

``` bash
cmake .. -DEASYSSL_STATIC_SSL=1
```

## Usage

### Initialize

The EasySSL library has the global `init` method that must be called before
using of the library and the `version` method that returns the current library
version:

```cpp
#include <easyssl.h>

int main() {
    if (!EasySSL::init()) {
        qCritical() << "EasySSL init failed";
        return -1;
    }

    qInfo() << "EasySSL version:" << EasySSL::version();
    // ...
}
```

### RSA: keys, encryption and signing

The `EasySSL::RSASSL` class is the RSA implementation of the `EasySSL::ICrypto`
interface. By default it uses the `PKCS1_OAEP_PADDING` padding mode.

```cpp
#include <easyssl/rsassl.h>
#include <QByteArray>
#include <QDebug>

int main() {
    // Create the public and private keys.
    EasySSL::RSASSL crypto;
    QByteArray pub, priv;

    if (!crypto.makeKeys(pub, priv)) {
        qCritical() << "Can not create RSA keys";
        return -1;
    }

    QByteArray message = "Hello EasySSL!";

    // Encryption and decryption.
    QByteArray encryptedMsg = crypto.encrypt(message, pub);
    QByteArray decryptedMsg = crypto.decrypt(encryptedMsg, priv);

    qInfo() << "Encrypted size:" << encryptedMsg.size();
    qInfo() << "Decrypted message:" << decryptedMsg;

    // Signing and checking the sign.
    QByteArray signature = crypto.signMessage(message, priv);

    if (crypto.checkSign(message, signature, pub)) {
        qInfo() << "The message sign is valid";
    }

    return 0;
}
```

> **Note:** the `RSASSL` default configuration uses the 3072 bits key size
> and the `PKCS1_OAEP_PADDING` padding mode (the recommended mode for new
> applications).

> **Warning:** RSA can encrypt only small messages (no more than the key size
> minus the padding overhead). To encrypt the big data you should use a
> symmetric cipher with a random key that is encrypted with the public key.

### ECDSA: signing

The `EasySSL::ECDSASSL` class is the ECDSA implementation of the
`EasySSL::ICrypto` interface. The ECDSA supports only the signing feature
(the `encrypt` and `decrypt` methods are not implemented).

```cpp
#include <easyssl/ecdsassl.h>
#include <QByteArray>
#include <QDebug>

int main() {
    // Create the ECDSA crypto object. The default curve is P-256.
    EasySSL::ECDSASSL crypto;

    QByteArray pub, priv;
    crypto.makeKeys(pub, priv);

    QByteArray message = "Hello ECDSA!";
    QByteArray signature = crypto.signMessage(message, priv);

    if (crypto.checkSign(message, signature, pub)) {
        qInfo() << "The message sign is valid";
    }

    return 0;
}
```


### X509: self-signed certificates

The `EasySSL::X509` class is the self-signed X509 certificate generator. The
certificate is generated with the public/private keys of the crypto object
that is passed to the constructor.

```cpp
#include <easyssl/x509.h>
#include <easyssl/ecdsassl.h>
#include <QSharedPointer>
#include <QDebug>

int main() {
    // Create the keys generator.
    auto crypto = QSharedPointer<EasySSL::ECDSASSL>(new EasySSL::ECDSASSL());

    // Create the certificate generator.
    EasySSL::X509 certificate(crypto);

    // Prepare the certificate data.
    EasySSL::SslSrtData data;
    data.country = "BY";
    data.organization = "QuasarApp";
    data.commonName = "easyssl.example.org";
    data.endTime = 31536000L; // 1 year

    // Create the self-signed certificate.
    auto cert = certificate.create(data);

    if (cert.crt.isNull()) {
        qCritical() << "Can not create the certificate";
        return -1;
    }

    qInfo() << "Certificate subject:" << cert.crt.subjectDisplayName();
    qInfo() << "Certificate is self-signed:" << cert.crt.isSelfSigned();
    qInfo() << "Certificate expiry date:" << cert.crt.expiryDate();

    return 0;
}
```

### Async authentication

The `EasySSL::AsyncKeysAuth<Crypto>` template class provides the asynchronous
authentication based on the pair of the asymmetric keys. The
`EasySSL::AuthECDSA` typedef is the ready ECDSA implementation of this class.

How it works:

* **Client:** creates the keys pair, signs the data `SHA256{unixTime + publicKey}`
  with the private key and sends to the server the request
  `{unixTime, signature, publicKey}`.
* **Server:** receives the request, checks that the `unixTime` is in the
  allowed time range, recalculate the `SHA256{unixTime + publicKey}` value and
  checks the signature with the public key. If the sign is valid, the server
  accepts the auth and creates (or logins) the user with the ID
  `sha256(publicKey)`.

```cpp
#include <easyssl/authecdsa.h>
#include <QByteArray>
#include <QString>
#include <QDebug>

// The AsyncKeysAuth template is an abstract class. The user must
// implement the getPrivateKey() method for the concrete crypto object.
class MyECDSA: public EasySSL::AuthECDSA {
public:

    void setPrivateKey(const QByteArray &newPriv) {
        _priv = newPriv;
    }

    QByteArray getPrivateKey() const override {
        return _priv;
    }

private:
    QByteArray _priv;
};

// The server receives the signature of the client from the network.
// The AsyncKeysAuth::setSignature method is protected, so the server
// side object must expose it in a public wrapper method.
class MyServerECDSA: public EasySSL::AuthECDSA {
public:

    QByteArray getPrivateKey() const override {
        return {};
    }

    // Public wrapper around the protected setSignature method.
    void setClientSignature(const QByteArray &signature) {
        setSignature(signature);
    }
};

int main() {
    // The client part.
    MyECDSA client;

    QByteArray pub, priv;
    client.makeKeys(pub, priv);
    client.setPrivateKey(priv);
    client.setPublicKey(pub);

    // Prepare the auth request (it must be done on the client side).
    if (!client.prepare()) {
        qCritical() << "Can not prepare the auth request";
        return -1;
    }

    // Send the client.unixTime(), client.signature() and client.publicKey()
    // values to the server. After that the client must clear the
    // private key: client.setPrivateKey({});

    // The server part. The server receives the request and creates
    // the authentication object with the client data.
    MyServerECDSA server;
    server.setPublicKey(pub);
    server.setUnixTime(client.unixTime());
    server.setClientSignature(client.signature());

    QString userID;

    // Check the auth. The 1000 is the allowed time difference in seconds.
    if (server.auth(1000, &userID)) {
        qInfo() << "User" << userID << "is logined";
    } else {
        qCritical() << "The auth failed";
        return -1;
    }

    // The user id is the SHA-256 hash of the client public key.
    if (userID != client.getUserId()) {
        qCritical() << "User id mismatch";
        return -1;
    }

    return 0;
}
```

## More information

* Full doxygen documentation: [here](https://quasarapp.ddns.net:3031/docs/QuasarApp/easyssl/latest/index.html)
* Migration from the Qt-Secret library: [MIGRATION_FROM_QT_SECRET.md](MIGRATION_FROM_QT_SECRET.md)
* Contributing: [CONTRIBUTING.md](../CONTRIBUTING.md)

