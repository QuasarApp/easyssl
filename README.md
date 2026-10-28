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

### Build without the system OpenSSL (BUILD_WITH_OPENSSL)

 By default the OpenSSL library is built together with the EasySSL library
 (the **BUILD_WITH_OPENSSL** option is enabled). In this case the EasySSL
 project clones the OpenSSL `openssl-4.0.3` sources, builds the static
 OpenSSL libraries and links them privately into the EasySSL binary. So
 your application has no runtime dependency on the system OpenSSL.

 To use the OpenSSL library that is installed on the system (or the target
 device) instead of the self-built one, set the **BUILD_WITH_OPENSSL**
 option to false (the system needs the OpenSSL 3.0+ library):

 ``` bash
 cmake .. -DBUILD_WITH_OPENSSL=0
 ```

 * Supported platforms: Linux, Windows (MinGW), Android, iOS and macOS (arm/x86).
 * The WASM platform is **not** supported.
 * On Windows the build requires the MinGW (GNU) compiler and the
   `mingw32-make` tool. The OpenSSL Configure script also requires a perl
   that produces Unix-like paths and that provides the perl core modules
   (for example the MSYS2 perl; set the `MSYS2_ROOT` environment variable
   to the MSYS2 installation directory if it is not found automatically).
 * The OpenSSL version can be changed with the `EASYSSL_OPENSSL_TAG` option
   (default `openssl-4.0.3`; the OpenSSL 3.0.x tags, for example
   `openssl-3.0.9`, are also supported).

### Unit tests

 The unit tests of the EasySSL library are built and run by default. To
 disable the tests, set the **EASYSSL_TESTS** option to false:

 ``` bash
 cmake .. -DEASYSSL_TESTS=0
 ```

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

* [EasySSL on the web](https://quasarapp.github.io/easyssl/) — the GitHub
  Pages site of this repository: the landing page and the full API reference
  generated automatically with Doxygen.
* [Usage and working examples](https://github.com/QuasarApp/easyssl/blob/main/docs/USAGE.md) —
  build with CMake and qmake, RSA/ECDSA examples, X509 certificates, async authentication.
* [Migration from the Qt-Secret library](https://github.com/QuasarApp/easyssl/blob/main/docs/MIGRATION_FROM_QT_SECRET.md) —
  API mapping, before/after code examples, key and signature format changes.

## Do not forget to help us make this library better...
See our main documentation about contributing to [EasySSL](https://github.com/QuasarApp/easyssl/blob/main/CONTRIBUTING.md)

Full documentation and the API reference available on the [EasySSL GitHub Pages](https://quasarapp.github.io/easyssl/) site.
