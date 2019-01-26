#ifndef CERTIFICATEREQUESTFACTORY_H_
#define CERTIFICATEREQUESTFACTORY_H_

#include <string>

class CertificateRequestSPKAC;

class CertificateRequestFactory {
public:
	static CertificateRequestSPKAC* fromSPKAC(std::string &path);
};

#endif /* CERTIFICATEREQUESTFACTORY_H_ */
