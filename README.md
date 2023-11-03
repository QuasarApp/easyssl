# EasySSL
This is wrapper library that make using OpenSSL library more simple.
This library contains interfaces for the signing and encryption data.

### Supported encryption algorithms:
* ECDSA
* RSA

### Supported features
* encryption
* signing
* keys creating
* asyn auth bse on the asyn encryptions methods


## Build and Include

 * cd yourRepo
 * git submodule add https://github.com/QuasarApp/easyssl.git # add the repository of Heart into your repo like submodule
 * git submodule update --init --recursive
 * Include in your CMakeLists.txt file the main CMakeLists.txt file of Heart library

     ```cmake
     add_subdirectory(easyssl)
     ```

 * link the Heart library to your target
     ```cmake
     target_link_libraries(yourLib PUBLIC easyssl)
     ```
 * rebuild yuor project



## Usage

### Encryption

```cpp
#include "easyssl/rsassl.h"

// create a publick and private keys array.
int main() {
    QByteArray pub, priv;
    EasySSL::RSASSL crypto;
    crypto.makeKeys(pub, priv)

    auto siganture = crypto.signMessage(message, priv);
    crypto.checkSign(message, siganture, pub);

    auto encryptedMsg = crypto.encrypt(message, pub);
    auto decryptedMsg = crypto.decrypt(encryptedMsg, priv);
}


```


### Authentication

```cpp
#include <easyssl/authecdsa.h>

class ECDSA: public EasySSL::AuthECDSA {

public:

    // AsyncKeysAuth interface
    void setPrivateKey(const QByteArray &newPriv) {
        _priv = newPriv;
    }

    QByteArray getPrivateKey() const {
        return _priv;
    };

private:
    QByteArray _priv;

};

ECDSA edsa;
QByteArray pub, priv;
QString userID;

// make public and private keys.
edsa.makeKeys(pub, priv);
edsa.setPrivateKey(priv);
edsa.setPublicKey(pub);

// prepare an authentication object.
edsa.prepare();
edsa.setPrivateKey({});

edsa.auth(1000, &userID)

```

## Do not forget to help us make this library better...
See our main documentation about contributing to [EasySsl](https://github.com/QuasarApp/easyssl/blob/main/CONTRIBUTING.md)

Full documentation available [here](https://quasarapp.ddns.net:3031/docs/QuasarApp/easyssl/latest/index.html)
