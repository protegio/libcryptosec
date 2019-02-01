#include <libcryptosec/certificate/CertificateRevocationList.h>

#include <libcryptosec/certificate/extension/ExtensionFactory.h>
#include <libcryptosec/Base64.h>
#include <libcryptosec/exception/EncodeException.h>

#include <openssl/pem.h>

CertificateRevocationList::CertificateRevocationList(const X509_CRL *crl) :
		crl(X509_CRL_dup((X509_CRL*) crl))
{
	THROW_DECODE_ERROR_IF(this->crl == NULL);
}

CertificateRevocationList::CertificateRevocationList(X509_CRL *crl) :
		crl(crl)
{
	THROW_DECODE_ERROR_IF(this->crl);
}

CertificateRevocationList::CertificateRevocationList(const std::string& pemEncoded)
{
	DECODE_PEM(this->crl, pemEncoded, PEM_read_bio_X509_CRL);
}

CertificateRevocationList::CertificateRevocationList(const ByteArray& derEncoded)
{
	DECODE_DER(this->crl, derEncoded, d2i_X509_CRL_bio);
}

CertificateRevocationList::CertificateRevocationList(const CertificateRevocationList& crl) :
		crl(X509_CRL_dup(crl.crl))
{
	THROW_DECODE_ERROR_IF(this->crl == NULL);
}

CertificateRevocationList::CertificateRevocationList(CertificateRevocationList&& crl) :
		crl(crl.crl)
{
	crl.crl = NULL;
}

CertificateRevocationList::~CertificateRevocationList()
{
	if (this->crl == NULL) {
		X509_CRL_free(this->crl);
	}
}

CertificateRevocationList& CertificateRevocationList::operator=(const CertificateRevocationList& crl)
{
	if (&crl == this) {
		return *this;
	}

	if (this->crl != NULL) {
		X509_CRL_free(this->crl);
	}

    this->crl = X509_CRL_dup(crl.crl);
    THROW_DECODE_ERROR_IF(this->crl == NULL);

    return *this;
}

CertificateRevocationList& CertificateRevocationList::operator=(CertificateRevocationList&& crl)
{
	if (&crl == this) {
		return *this;
	}

	if (this->crl != NULL) {
		X509_CRL_free(this->crl);
	}

    this->crl = crl.crl;
    crl.crl = NULL;

    return *this;
}

BigInteger CertificateRevocationList::getSerialNumber() const
{
	ASN1_INTEGER *asn1Int = (ASN1_INTEGER*) X509_CRL_get_ext_d2i(this->crl, NID_crl_number, 0, 0);
	THROW_DECODE_ERROR_IF(asn1Int == NULL);
	THROW_DECODE_ERROR_AND_FREE_IF(asn1Int->data == NULL,
			ASN1_INTEGER_free(asn1Int);
	);
	BigInteger ret(asn1Int);
	ASN1_INTEGER_free(asn1Int);
	return ret;
}

BigInteger CertificateRevocationList::getBaseCRLNumber() const
{
	ASN1_INTEGER *asn1Int = (ASN1_INTEGER*) X509_CRL_get_ext_d2i(this->crl, NID_delta_crl, 0, 0);
	THROW_DECODE_ERROR_IF(asn1Int == NULL);
	THROW_DECODE_ERROR_AND_FREE_IF(asn1Int->data == NULL,
			ASN1_INTEGER_free(asn1Int);
	);
	BigInteger ret(asn1Int);
	ASN1_INTEGER_free(asn1Int);
	return ret;
}

long CertificateRevocationList::getVersion() const
{
	// TODO: A verificação vai falhar para versões novas ou alternativas do X509
	long ret = X509_CRL_get_version(this->crl);
	THROW_DECODE_ERROR_IF(ret < 0 || ret > 1);
	return ret;
}

RDNSequence CertificateRevocationList::getIssuer() const
{
	const X509_NAME *name = X509_CRL_get_issuer(this->crl);
	THROW_DECODE_ERROR_IF(name == NULL);
	return RDNSequence(name);
}

DateTime CertificateRevocationList::getLastUpdate() const
{
	const ASN1_TIME *date = X509_CRL_get0_lastUpdate(this->crl);
	THROW_DECODE_ERROR_IF(date == NULL);
	return DateTime(date);
}

DateTime CertificateRevocationList::getNextUpdate() const
{
	const ASN1_TIME *date = X509_CRL_get0_nextUpdate(this->crl);
	THROW_DECODE_ERROR_IF(date == NULL);
	return DateTime(date);
}

std::vector<RevokedCertificate> CertificateRevocationList::getRevokedCertificates() const
{
	std::vector<RevokedCertificate> ret;
    STACK_OF(X509_REVOKED)* revokedStack = X509_CRL_get_REVOKED(this->crl);
    if (revokedStack == NULL) {
    	return ret;
    }

    int size = sk_X509_REVOKED_num(revokedStack);
    for (int i = 0; i < size; i++) {
    	const X509_REVOKED *sslRevoked = sk_X509_REVOKED_value(revokedStack, i);
    	THROW_DECODE_ERROR_IF(sslRevoked == NULL);
    	RevokedCertificate revoked(sslRevoked);
    	ret.push_back(revoked);
    }

    return ret;
}

bool CertificateRevocationList::verify(const PublicKey& publicKey) const
{
	int rc = X509_CRL_verify(this->crl, (EVP_PKEY*) publicKey.getEvpPkey());
	return (rc ? 1 : 0);
}

std::vector<Extension*> CertificateRevocationList::getExtension(Extension::Name extensionName) const
{
	std::vector<Extension*> ret;
	int size = X509_CRL_get_ext_count(this->crl);
	for (int i = 0; i < size; i++) {
		const X509_EXTENSION *ext = X509_CRL_get_ext(this->crl, i);
		THROW_DECODE_ERROR_AND_FREE_IF(ext == NULL,
				for (auto extension : ret) {
					delete extension;
				}
		);

		if (Extension::getName(ext) == extensionName) {
			Extension *oneExt = ExtensionFactory::getExtension(ext);
			ret.push_back(oneExt);
		}
	}
	return ret;
}

std::vector<Extension*> CertificateRevocationList::getExtensions() const
{
	std::vector<Extension*> ret;
	int size = X509_CRL_get_ext_count(this->crl);
	for (int i = 0; i < size; i++) {
		X509_EXTENSION *ext = X509_CRL_get_ext(this->crl, i);
		THROW_DECODE_ERROR_AND_FREE_IF(ext == NULL,
				for (auto extension : ret) {
					delete extension;
				}
		);

		Extension *oneExt = ExtensionFactory::getExtension(ext);
		ret.push_back(oneExt);
	}
	return ret;
}

std::vector<Extension*> CertificateRevocationList::getUnknownExtensions() const
{
	Extension *oneExt = NULL;
	std::vector<Extension*> ret;

	int size = X509_CRL_get_ext_count(this->crl);
	for (int i = 0; i < size; i++) {
		X509_EXTENSION *ext = X509_CRL_get_ext(this->crl, i);
		THROW_DECODE_ERROR_AND_FREE_IF(ext == NULL,
				for (auto extension : ret) {
					delete extension;
				}
		);

		switch (Extension::getName(ext)) {
			case Extension::UNKNOWN:
				oneExt = new Extension(ext);
				ret.push_back(oneExt);
				break;
			default:
				break;
		}
	}
	return ret;
}

std::string CertificateRevocationList::toXml(const std::string& tab) const
{
	std::stringstream ss;
	std::string ret, string;
	ByteArray data;
	std::vector<RevokedCertificate> revokedCertificates;

	ret = tab + "<certificateRevocationList>\n";
	ret += tab + "\t<tbsCertList>\n";
		try {  /* version */
			ss << this->getVersion();
			ret += tab + "\t\t<version>" + ss.str() + "</version>\n";
		} catch (...) {
		}

		try { /* Serial Number */
			ss.clear();
			ret += tab + "\t\t<serialNumber>" + this->getSerialNumber().toDec() + "</serialNumber>\n";
		} catch (...) {
		}

		ret += tab + "\t\t<issuer>\n";
			ret += (this->getIssuer()).toXml("\t\t\t");
		ret += tab + "\t\t</issuer>\n";
		ret += tab + "\t\t<lastUpdate>" + this->getLastUpdate().getXmlEncoded() + "</lastUpdate>\n";
		ret += tab + "\t\t<nextUpdate>" + this->getNextUpdate().getXmlEncoded() + "</nextUpdate>\n";
		ret += tab + "\t\t<revokedCertificates>\n";
			revokedCertificates = this->getRevokedCertificates();
			for (auto revoked : revokedCertificates) {
				ret += revoked.toXml(tab + "\t\t\t");
			}
		ret += tab + "\t\t</revokedCertificates>\n";
	ret += tab + "\t</tbsCertList>\n";
	ret += tab + "\t<signatureAlgorithm>\n";
		string = OBJ_nid2ln(X509_CRL_get_signature_nid(this->crl));
		ret += tab + "\t\t<algorithm>" + string + "</algorithm>\n";
	ret += tab + "\t</signatureAlgorithm>\n";

	const ASN1_BIT_STRING* signature = 0;
	X509_CRL_get0_signature(this->crl, &signature, 0);
	data = ByteArray(signature->data, signature->length);
	string = Base64::encode(data);
	ret += tab + "\t<signatureValue>" + string + "</signatureValue>\n";
	ret += tab + "</certificateRevocationList>\n";

	return ret;
}

std::string CertificateRevocationList::getPemEncoded() const
{
	ENCODE_PEM_AND_RETURN(this->crl, PEM_write_bio_X509_CRL);
}

ByteArray CertificateRevocationList::getDerEncoded() const
{
	ENCODE_DER_AND_RETURN(this->crl, i2d_X509_CRL_bio);
}

X509_CRL* CertificateRevocationList::getSslObject() const
{
	X509_CRL *crlClone = X509_CRL_dup(this->crl);
	THROW_ENCODE_ERROR_IF(crlClone == NULL);
	return crlClone;
}

const X509_CRL* CertificateRevocationList::getX509Crl() const
{
	return this->crl;
}
