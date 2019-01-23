#ifndef CERTIFICATEREQUEST_H_
#define CERTIFICATEREQUEST_H_

#include <openssl/x509.h>

#include <string>
#include <vector>

#include <libcryptosec/ByteArray.h>
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/PrivateKey.h>
#include <libcryptosec/PublicKey.h>

#include "RDNSequence.h"

#include "Extension.h"
#include "KeyUsageExtension.h"
#include "ExtendedKeyUsageExtension.h"
#include "BasicConstraintsExtension.h"
#include "CRLDistributionPointsExtension.h"
#include "AuthorityInformationAccessExtension.h"
#include "IssuerAlternativeNameExtension.h"
#include "SubjectAlternativeNameExtension.h"
#include "SubjectInformationAccessExtension.h"
#include "AuthorityKeyIdentifierExtension.h"
#include "SubjectKeyIdentifierExtension.h"
#include "CertificatePoliciesExtension.h"

class CertificateRequest
{
public:
	CertificateRequest();
	CertificateRequest(X509_REQ *req);
	CertificateRequest(std::string &pemEncoded);
	CertificateRequest(ByteArray &derEncoded);
	CertificateRequest(const CertificateRequest& req);
	virtual ~CertificateRequest();
	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	virtual std::string toXml(std::string tab = "");
	std::string getPemEncoded();
	ByteArray* getDerEncoded() const;
	MessageDigest::Algorithm getMessageDigestAlgorithm();
	void setVersion(long version);
	long getVersion();
	void setPublicKey(PublicKey &publicKey);
	PublicKey* getPublicKey();
	ByteArray getPublicKeyInfo();
	void setSubject(RDNSequence &name);
	RDNSequence getSubject();
	void addExtension(Extension &extension);
	void addExtensions(std::vector<Extension *> &extensions);
	void replaceExtension(Extension &extension);
	std::vector<Extension *> removeExtension(Extension::Name extensionName);
	std::vector<Extension *> removeExtension(ObjectIdentifier extOID);
	std::vector<Extension *> getExtension(Extension::Name extensionName);
	std::vector<Extension *> getExtensions();
	std::vector<Extension *> getUnknownExtensions();
	ByteArray* getFingerPrint(MessageDigest::Algorithm algorithm) const;
	void sign(PrivateKey &privateKey, MessageDigest::Algorithm messageDigestAlgorithm);
	virtual bool verify();
	virtual bool isSigned() const throw();
	X509_REQ* getX509Req() const;
	CertificateRequest& operator =(const CertificateRequest& value);
protected:
	X509_REQ *req;
};

#endif /*CERTIFICATEREQUEST_H_*/
