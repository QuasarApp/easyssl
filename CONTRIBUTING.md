# Contributing in to EasySSL

This is a wrap library for the Qt developers. So if you think that is a good library, and you use it in your projects - you can add new improvements and create a pull request with new features.

## What can you do for this Library ?

1. You can add a support of new encryption algorithms.
2. You can implement new certificate generator.

## Adding new implementation of crypto algorithms

All algorithms must pass simple test. Encrypt, decrypt short and long data arrays. This simple test is already implemented, and you just need to add it into the main test file.

### Example

Adding supporting RSA algorithm to this library.

1. Create implementation of the iCrypto interface.

   ```cpp

   #include "icrypto.h"

     /**
     * @brief The RSASSL class This is wrapper for RSA algorithm of openssl 3.0 libraryry.
     */
    class EASYSSL_EXPORT RSASSL: public EasySSL::ICrypto {

      // override main methods of the interface.
      EVP_PKEY *makeRawKeys() const override;
      Features supportedFeatures() const override;
      QSsl::KeyAlgorithm keyAlgorithm() const override;
      QByteArray signMessage(const QByteArray &inputData, const QByteArray &key) const override;
      bool checkSign(const QByteArray &inputData, const QByteArray &signature, const QByteArray &key) const override;
      QByteArray decrypt(const QByteArray &message, const QByteArray &key) override;
      QByteArray encrypt(const QByteArray &message, const QByteArray &key) override;

    }
   ```

Full implementation of the RSA you can see [here](https://github.com/QuasarApp/easyssl/blob/main/src/lib/src/public/easyssl/rsassl.h).

2. Add your class to the tests Using The Template class [CryptoTest](https://github.com/QuasarApp/easyssl/blob/main/tests/units/cryptotest.h). See The [tstMain.cpp](https://github.com/QuasarApp/easyssl/blob/main/tests/tstMain.cpp) file

```cpp
TestCase(cryptoTestRSA, CryptoTest<EasySSL::RSASSL>)
```

## Adding new implementation of Certificate generator.

1. Create implementation of the iCrypto interface. And override the create method.

```cpp
/**
 * @brief The X509 class This is wrapper of the ssl objects.
 */
class EASYSSL_EXPORT X509: public  EasySSL::ICertificate
{
public:
    X509(const QSharedPointer<ICrypto>& generator);

    // ICertificate interface
public:
    SelfSignedSertificate create(const SslSrtData& certificateData) const override;
};
```

Full implementation of x509 certificate format you can see [here](https://github.com/QuasarApp/easyssl/blob/main/src/lib/src/public/easyssl/x509.h).

2. Add your class to the tests Using The Template class [CrtTest](https://github.com/QuasarApp/easyssl/blob/main/tests/units/crttest.h). See The [tstMain.cpp](https://github.com/QuasarApp/easyssl/blob/main/tests/tstMain.cpp) file

```cpp
#include "crttest.h"

using CrtTestX509ECDSA = CrtTest<EasySSL::X509, EasySSL::ECDSASSL>;
TestCase(crtTestX509ECDSA, CrtTestX509ECDSA)
```

## Extra rools

1. All shared tools or useful functions located on the [EasySSLUtils](https://github.com/QuasarApp/easyssl/blob/main/src/lib/src/private/easysslutils.h) class.
2. All implementation must contain doxygen xml comments (documentation)
3. All implementation must be inner EasySSL name space.

# Thank you

