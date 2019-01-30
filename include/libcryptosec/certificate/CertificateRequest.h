#ifndef CERTIFICATEREQUEST_H_
#define CERTIFICATEREQUEST_H_

#include <libcryptosec/certificate/RDNSequence.h>
#include <libcryptosec/certificate/extension/Extension.h>
#include <libcryptosec/PrivateKey.h>
#include <libcryptosec/PublicKey.h>
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/ByteArray.h>

#include <openssl/x509.h>

#include <string>
#include <vector>

class Extension;

class CertificateRequest
{
protected:
	CertificateRequest(X509_REQ* req);

public:
	CertificateRequest();
	CertificateRequest(const X509_REQ* req);
	CertificateRequest(const std::string& pemEncoded);
	CertificateRequest(const ByteArray& derEncoded);

	CertificateRequest(const CertificateRequest& req);
	CertificateRequest(CertificateRequest&& req);

	virtual ~CertificateRequest();

	CertificateRequest& operator=(const CertificateRequest& value);
	CertificateRequest& operator=(CertificateRequest&& value);

	MessageDigest::Algorithm getMessageDigestAlgorithm() const;

	void setVersion(long version);
	long getVersion() const;

	void setPublicKey(const PublicKey& publicKey);
	PublicKey getPublicKey() const;
	ByteArray getPublicKeyInfo() const;

	void setSubject(const RDNSequence& name);
	RDNSequence getSubject() const;

	void addExtension(const Extension& extension);
	void addExtensions(const std::vector<Extension*>& extensions);
	void replaceExtension(const Extension& extension);
	std::vector<Extension*> removeExtension(Extension::Name extensionName);
	std::vector<Extension*> removeExtension(const ObjectIdentifier& extOID);
	std::vector<Extension*> getExtension(Extension::Name extensionName) const;
	std::vector<Extension*> getExtensions() const;
	std::vector<Extension*> getUnknownExtensions() const;

	ByteArray getFingerPrint(MessageDigest::Algorithm algorithm) const;

	void sign(const PrivateKey &privateKey, MessageDigest::Algorithm messageDigestAlgorithm);
	virtual bool verify() const;
	virtual bool isSigned() const;

	std::string getPemEncoded() const;
	ByteArray getDerEncoded() const;

	virtual std::string toXml(const std::string& tab = "") const;

	X509_REQ* getSslObject() const;
	const X509_REQ* getX509Req() const;

protected:
	X509_REQ *req;
};

#endif /*CERTIFICATEREQUEST_H_*/
