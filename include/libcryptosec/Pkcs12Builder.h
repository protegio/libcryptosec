#ifndef PKCS12BUILDER_H_
#define PKCS12BUILDER_H_

#include "PrivateKey.h"
#include <libcryptosec/certificate/Certificate.h>
#include "Pkcs12.h"
#include <libcryptosec/exception/Pkcs12Exception.h>

class Pkcs12Builder
{
public:
	Pkcs12Builder();
	virtual ~Pkcs12Builder();
	
	void setKeyAndCertificate(PrivateKey* key, Certificate* cert, std::string friendlyName = std::string("")) throw();
	void setAdditionalCerts(std::vector<Certificate*> certs) throw();
	void addAdditionalCert(Certificate* cert) throw();
	void clearAdditionalCerts() throw();
	Pkcs12* doFinal(std::string password = std::string("")) const;
	
protected:
	std::string friendlyName;
	PrivateKey* key;
	Certificate* keyCert;
	std::vector<Certificate*> certs;
};

#endif /*PKCS12BUILDER_H_*/
