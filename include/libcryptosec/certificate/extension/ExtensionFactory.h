#ifndef SRC_CERTIFICATE_EXTENSIONFACTORY_H_
#define SRC_CERTIFICATE_EXTENSIONFACTORY_H_

#include <openssl/x509.h>

class Extension;

class ExtensionFactory {
public:
	virtual ~ExtensionFactory();
	static Extension* getExtension(const X509_EXTENSION* ext);
};

#endif /* SRC_CERTIFICATE_EXTENSIONFACTORY_H_ */
