# EasySSL
This is simple wrapper library that make using ssl simple. 
This library contains interfaces for the signing and encription data.

### Supported encription alhorithms:
* edsa based on sll 1.1 

### Supported features
* encription 
* signing
* keys creating
* asyn auth bse on the asyn encriptions methods


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

Authentication 

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

Full documentation available [here](https://quasarapp.ddns.net:3031/docs/QuasarApp/easyssl/latest/index.html) 
