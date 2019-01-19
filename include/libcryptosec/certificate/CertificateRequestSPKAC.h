#ifndef CERTIFICATEREQUESTSPKAC_H_
#define CERTIFICATEREQUESTSPKAC_H_

#include <libcryptosec/certificate/CertificateRequest.h>
#include <libcryptosec/NetscapeSPKI.h>

class CertificateRequestSPKAC: public CertificateRequest {
public:
	CertificateRequestSPKAC(std::string &netscapeSPKIBase64);
	CertificateRequestSPKAC(X509_REQ *req, NETSCAPE_SPKI *netscapeSPKI);
	CertificateRequestSPKAC(std::string &certificateRequestPemEncoded, std::string &netscapeSPKIBase64);
	virtual ~CertificateRequestSPKAC();

	bool verify();
	bool isSigned() const throw();
protected:
	NetscapeSPKI* spkac;
};

#endif /* CERTIFICATEREQUESTSPKAC_H_ */
