#include <libcryptosec/certificate/CertificateRequestSPKAC.h>

CertificateRequestSPKAC::CertificateRequestSPKAC(std::string &netscapeSPKIBase64) : CertificateRequest()
{
	this->spkac = new NetscapeSPKI(netscapeSPKIBase64);
	this->setPublicKey(*this->spkac->getPublicKey());
}

CertificateRequestSPKAC::CertificateRequestSPKAC(X509_REQ *req, NETSCAPE_SPKI *netscapeSPKI) : CertificateRequest(req) {
	this->spkac = new NetscapeSPKI(netscapeSPKI);
	this->setPublicKey(*this->spkac->getPublicKey());
}

CertificateRequestSPKAC::CertificateRequestSPKAC(std::string &certificateRequestPemEncoded, std::string &netscapeSPKIBase64) : CertificateRequest(certificateRequestPemEncoded)
{
	this->spkac = new NetscapeSPKI(netscapeSPKIBase64);
	this->setPublicKey(*this->spkac->getPublicKey());
}

CertificateRequestSPKAC::~CertificateRequestSPKAC() {
	if(this->spkac)
		delete this->spkac;
}

bool CertificateRequestSPKAC::verify()
{
	return this->spkac->verify();
}
bool CertificateRequestSPKAC::isSigned() const throw()
{
	return this->spkac->isSigned();
}
