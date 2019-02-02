#ifndef PKCS12BUILDER_H_
#define PKCS12BUILDER_H_

#include <libcryptosec/pkcs12/Pkcs12.h>
#include <libcryptosec/certificate/Certificate.h>
#include <libcryptosec/PrivateKey.h>

#include <vector>
#include <string>

class Pkcs12Builder
{
public:
	Pkcs12Builder(const PrivateKey& key, const Certificate& cert,
			const std::string& friendlyName = "");
	virtual ~Pkcs12Builder();
	
	void setKeyAndCertificate(const PrivateKey& key, const Certificate& cert,
			const std::string& friendlyName = "");

	void setAdditionalCerts(const std::vector<Certificate>& certs);
	void addAdditionalCert(const Certificate& cert);
	void clearAdditionalCerts();
	Pkcs12 doFinal(const std::string& password = "");
	
protected:
	PrivateKey key;
	Certificate cert;
	std::string friendlyName;
	std::vector<Certificate> certs;
};

#endif /*PKCS12BUILDER_H_*/
