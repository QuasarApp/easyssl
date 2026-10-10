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
* async auth based on the asymmetric encryption methods


## Build and Include
### CMake

 * cd yourRepo
 * git submodule add https://github.com/QuasarApp/easyssl.git # add the repository of EasySSL into your repo like submodule
 * git submodule update --init --recursive
 * Include in your CMakeLists.txt file the main CMakeLists.txt file of EasySSL library

     ```cmake
     add_subdirectory(easyssl)
     ```

 * link the EasySSL library to your target
     ```cmake
     target_link_libraries(yourLib PUBLIC easyssl)
     ```
 * rebuild your project

### Independent of SSL build
Dependency on the ssl library greatly complicates the deployment of the final product. For fix this issue, you can build EasySSL library with static SSL library. In this case, SSL library code will be saved in your EasySSL binary, and deploy of your application will be easily. The ssl code will not available for your application or other libraries, so you will not get conflicts between different major versions ssl libraries if your distribution kit has it.  

Just set the **EASYSSL_STATIC_SSL** option to true. 

``` bash
cmake .. -DEASYSSL_STATIC_SSL=1 
```

The described case may be useful for the Qt 5.15.x, because the QNetwork 5.15 depends on the SSL v1.1 and EasySSL works with the SSL >= 3.0. 

## Usage

### Encryption

```cpp
#include <easyssl/rsassl.h>
#include <QByteArray>

int main() {
    // create a public and private keys array.
    EasySSL::RSASSL crypto;
    QByteArray pub, priv;
    crypto.makeKeys(pub, priv);

    QByteArray message = "Hello EasySSL!";

    auto signature = crypto.signMessage(message, priv);
    crypto.checkSign(message, signature, pub);

    auto encryptedMsg = crypto.encrypt(message, pub);
    auto decryptedMsg = crypto.decrypt(encryptedMsg, priv);
}
```

More information about the build options (CMake, qmake) and the usage examples
(RSA, ECDSA, X509 certificates, async authentication) is available in the
[docs/USAGE.md](docs/USAGE.md) file.


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
    }

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

edsa.auth(1000, &userID);

```

## Documentation

* [Usage and working examples](docs/USAGE.md) — build with CMake and qmake,
  RSA/ECDSA examples, X509 certificates, async authentication.
* [Migration from the Qt-Secret library](docs/MIGRATION_FROM_QT_SECRET.md) —
  API mapping, before/after code examples, key and signature format changes.

## Do not forget to help us make this library better...
See our main documentation about contributing to [EasySSL](https://github.com/QuasarApp/easyssl/blob/main/CONTRIBUTING.md)

Full documentation available [here](https://quasarapp.ddns.net:3031/docs/QuasarApp/easyssl/latest/index.html)
