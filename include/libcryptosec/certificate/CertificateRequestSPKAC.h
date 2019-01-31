#ifndef CERTIFICATEREQUESTSPKAC_H_
#define CERTIFICATEREQUESTSPKAC_H_

#include <libcryptosec/certificate/CertificateRequest.h>
#include <libcryptosec/NetscapeSPKI.h>

class CertificateRequestSPKAC: public CertificateRequest {
public:
	CertificateRequestSPKAC(const std::string& netscapeSPKIBase64);
	CertificateRequestSPKAC(const X509_REQ* req, const NETSCAPE_SPKI* netscapeSPKI);
	CertificateRequestSPKAC(const std::string& certificateRequestPemEncoded, const std::string& netscapeSPKIBase64);

	virtual ~CertificateRequestSPKAC();

	bool verify() const;
	bool isSigned() const;

protected:
	NetscapeSPKI spkac;
};

#endif /* CERTIFICATEREQUESTSPKAC_H_ */
