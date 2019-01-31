#include <libcryptosec/certificate/CertificateRequestSPKAC.h>

CertificateRequestSPKAC::CertificateRequestSPKAC(const std::string& netscapeSPKIBase64) :
		CertificateRequest(), spkac(netscapeSPKIBase64)
{
	this->setPublicKey(this->spkac.getPublicKey());
}

CertificateRequestSPKAC::CertificateRequestSPKAC(const X509_REQ* req, const NETSCAPE_SPKI* netscapeSPKI) :
		CertificateRequest(req), spkac(netscapeSPKI)
{
	this->setPublicKey(this->spkac.getPublicKey());
}

CertificateRequestSPKAC::CertificateRequestSPKAC(const std::string& certificateRequestPemEncoded, const std::string& netscapeSPKIBase64) :
		CertificateRequest(certificateRequestPemEncoded), spkac(netscapeSPKIBase64)
{
	this->setPublicKey(this->spkac.getPublicKey());
}

CertificateRequestSPKAC::~CertificateRequestSPKAC()
{
}

bool CertificateRequestSPKAC::verify() const
{
	return this->spkac.verify();
}
bool CertificateRequestSPKAC::isSigned() const
{
	return this->spkac.isSigned();
}
