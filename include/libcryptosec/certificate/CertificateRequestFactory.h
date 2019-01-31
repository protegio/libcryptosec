#ifndef CERTIFICATEREQUESTFACTORY_H_
#define CERTIFICATEREQUESTFACTORY_H_

#include <libcryptosec/certificate/CertificateRequestSPKAC.h>

#include <string>

class CertificateRequestFactory {
public:
	static CertificateRequestSPKAC fromSPKAC(const std::string& path);
};

#endif /* CERTIFICATEREQUESTFACTORY_H_ */
