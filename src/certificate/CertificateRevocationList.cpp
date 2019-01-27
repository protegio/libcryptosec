#include <libcryptosec/certificate/CertificateRevocationList.h>

#include <libcryptosec/certificate/extension/Extension.h>
#include <libcryptosec/certificate/extension/ExtensionFactory.h>
#include <libcryptosec/Base64.h>
#include <libcryptosec/exception/EncodeException.h>

#include <openssl/pem.h>

CertificateRevocationList::CertificateRevocationList(const X509_CRL *crl) :
		crl(X509_CRL_dup((X509_CRL*) crl))
{
	if (this->crl == NULL) {
		throw CertificationException("" /* TODO */);
	}
}

CertificateRevocationList::CertificateRevocationList(X509_CRL *crl) :
		crl(crl)
{
	if (this->crl == NULL) {
		throw CertificationException("" /* TODO */);
	}
}

CertificateRevocationList::CertificateRevocationList(const std::string& pemEncoded)
{
	BIO *buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL) {
		throw EncodeException(EncodeException::BUFFER_CREATING, "CertificateRevocationList::CertificateRevocationList");
	}

	unsigned int numberOfBytes = BIO_write(buffer, pemEncoded.c_str(), pemEncoded.size());
	if (numberOfBytes != pemEncoded.size()) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "CertificateRevocationList::CertificateRevocationList");
	}

	this->crl = PEM_read_bio_X509_CRL(buffer, NULL, NULL, NULL);
	if (this->crl == NULL) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_DECODE, "CertificateBuilder::CertificateBuilder");
	}

	BIO_free(buffer);
}

CertificateRevocationList::CertificateRevocationList(const ByteArray& derEncoded)
{
	BIO *buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL) {
		throw EncodeException(EncodeException::BUFFER_CREATING, "CertificateRevocationList::CertificateRevocationList");
	}

	unsigned int numberOfBytes = BIO_write(buffer, derEncoded.getConstDataPointer(), derEncoded.getSize());
	if (numberOfBytes != derEncoded.getSize()) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "CertificateRevocationList::CertificateRevocationList");
	}

	this->crl = d2i_X509_CRL_bio(buffer, NULL); /* TODO: will the second parameter work fine ? */
	if (this->crl == NULL) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_DECODE, "CertificateRevocationList::CertificateRevocationList");
	}

	BIO_free(buffer);
}

CertificateRevocationList::CertificateRevocationList(const CertificateRevocationList& crl)
{
	this->crl = X509_CRL_dup(crl.getX509Crl());
}

CertificateRevocationList::~CertificateRevocationList()
{
	if (this->crl == nullptr) {
		X509_CRL_free(this->crl);
	}
}

CertificateRevocationList& CertificateRevocationList::operator=(const CertificateRevocationList& value)
{
	if (&value == this) {
		return *this;
	}

	if (this->crl) {
		X509_CRL_free(this->crl);
	}

    this->crl = X509_CRL_dup(value.crl);

    return *this;
}

std::string CertificateRevocationList::getXmlEncoded(const std::string& tab) const
{
	std::string ret, string;
	ByteArray data;
	char temp[11];
	std::vector<RevokedCertificate> revokedCertificates;

	ret = tab + "<certificateRevocationList>\n";
	ret += tab + "\t<tbsCertList>\n";
		try {  /* version */
			sprintf(temp, "%d", (int)this->getVersion());
			ret += tab + "\t\t<version>" + temp + "</version>\n";
		} catch (...) {
		}

		try { /* Serial Number */
			sprintf(temp, "%d", (int)this->getSerialNumber());
			ret += tab + "\t\t<serialNumber>" + temp + "</serialNumber>\n";
		} catch (...) {
		}

		ret += tab + "\t\t<issuer>\n";
			ret += (this->getIssuer()).getXmlEncoded("\t\t\t");
		ret += tab + "\t\t</issuer>\n";
		ret += tab + "\t\t<lastUpdate>" + this->getLastUpdate().getXmlEncoded() + "</lastUpdate>\n";
		ret += tab + "\t\t<nextUpdate>" + this->getNextUpdate().getXmlEncoded() + "</nextUpdate>\n";
		ret += tab + "\t\t<revokedCertificates>\n";
			revokedCertificates = this->getRevokedCertificates();
			for (auto revoked : revokedCertificates) {
				ret += revoked.getXmlEncoded(tab + "\t\t\t");
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
	unsigned char *data = NULL;

	BIO *buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL) {
		throw EncodeException(EncodeException::BUFFER_CREATING, "CertificateRevocationList::getPemEncoded");
	}

	int wrote = PEM_write_bio_X509_CRL(buffer, this->crl);
	if (!wrote) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_ENCODE, "CertificateRevocationList::getPemEncoded");
	}

	int ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "CertificateRevocationList::getPemEncoded");
	}

	ByteArray ret(data, ndata);
	BIO_free(buffer);

	return ret.toString();
}

ByteArray CertificateRevocationList::getDerEncoded() const
{
	unsigned char *data = NULL;

	BIO *buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL) {
		throw EncodeException(EncodeException::BUFFER_CREATING, "CertificateRevocationList::getDerEncoded");
	}

	int wrote = i2d_X509_CRL_bio(buffer, this->crl);
	if (!wrote) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_ENCODE, "CertificateRevocationList::getDerEncoded");
	}

	int ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "CertificateRevocationList::getDerEncoded");
	}

	ByteArray ret(data, ndata);
	BIO_free(buffer);

	return ret;
}

long CertificateRevocationList::getSerialNumber() const
{
	if (this->crl == NULL) {
		throw CertificationException(CertificationException::INVALID_CRL, "CertificateRevocationList::getSerialNumber");
	}

	ASN1_INTEGER *asn1Int = (ASN1_INTEGER*) X509_CRL_get_ext_d2i(this->crl, NID_crl_number, 0, 0);
	if (asn1Int == NULL) {
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateRevocationList::getSerialNumber");
	}

	if (asn1Int->data == NULL) {
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationList::getSerialNumber");
	}

	long ret = ASN1_INTEGER_get(asn1Int);
	if (ret < 0L) {
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationList::getSerialNumber");
	}

	return ret;
}

BigInteger CertificateRevocationList::getSerialNumberBigInt() const
{
	if (this->crl == NULL) {
		throw CertificationException(CertificationException::INVALID_CRL, "CertificateRevocationList::getSerialNumber");
	}

	ASN1_INTEGER *asn1Int = (ASN1_INTEGER*) X509_CRL_get_ext_d2i(this->crl, NID_crl_number, 0, 0);
	if (asn1Int == NULL) {
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateRevocationList::getSerialNumber");
	}

	if (asn1Int->data == NULL) {
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationList::getSerialNumber");
	}

	return BigInteger(asn1Int);
}

long CertificateRevocationList::getBaseCRLNumber() const
{
	if (this->crl == NULL) {
		throw CertificationException(CertificationException::INVALID_CRL, "CertificateRevocationList::getBaseCRLNumber");
	}

	ASN1_INTEGER *asn1Int = (ASN1_INTEGER*) X509_CRL_get_ext_d2i(this->crl, NID_delta_crl, 0, 0);
	if (asn1Int == NULL) {
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateRevocationList::getBaseCRLNumber");
	}

	if (asn1Int->data == NULL) {
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationList::getBaseCRLNumber");
	}

	long ret = ASN1_INTEGER_get(asn1Int);
	if (ret < 0L) {
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationList::getBaseCRLNumber");
	}

	return ret;
}

BigInteger CertificateRevocationList::getBaseCRLNumberBigInt() const
{
	if (this->crl == NULL) {
		throw CertificationException(CertificationException::INVALID_CRL, "CertificateRevocationList::getBaseCRLNumberBigInt");
	}

	ASN1_INTEGER *asn1Int = (ASN1_INTEGER*) X509_CRL_get_ext_d2i(this->crl, NID_delta_crl, 0, 0);
	if (asn1Int == NULL) {
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateRevocationList::getBaseCRLNumberBigInt");
	}

	if (asn1Int->data == NULL) {
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationList::getBaseCRLNumberBigInt");
	}

	return BigInteger(asn1Int);
}


long CertificateRevocationList::getVersion() const
{
	if (this->crl == NULL) {
		throw CertificationException(CertificationException::INVALID_CRL, "CertificateRevocationList::getVersion");
	}

	// TODO: A verificação vai falhar para versões novas ou alternativas do X509
	long ret = X509_CRL_get_version(this->crl);
	if (ret < 0 || ret > 1) {
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateRevocationList::getVersion");
	}

	return ret;
}

RDNSequence CertificateRevocationList::getIssuer() const
{
	return RDNSequence(X509_CRL_get_issuer(this->crl));
}

DateTime CertificateRevocationList::getLastUpdate() const
{
	return DateTime(X509_CRL_get0_lastUpdate(this->crl));
}

DateTime CertificateRevocationList::getNextUpdate() const
{
	return DateTime(X509_CRL_get0_nextUpdate(this->crl));
}

std::vector<RevokedCertificate> CertificateRevocationList::getRevokedCertificates() const
{
	std::vector<RevokedCertificate> ret;
    STACK_OF(X509_REVOKED)* revokedStack = X509_CRL_get_REVOKED(this->crl);
    int size = sk_X509_REVOKED_num(revokedStack);
    for (int i = 0; i < size; i++) {
    	const X509_REVOKED *revoked = sk_X509_REVOKED_value(revokedStack, i);
    	ret.push_back(RevokedCertificate(revoked));
    }
    return ret;
}

bool CertificateRevocationList::verify(const PublicKey& publicKey) const
{
	int rc = X509_CRL_verify(this->crl, (EVP_PKEY*) publicKey.getEvpPkey());
	return (rc ? 1 : 0);
}

X509_CRL* CertificateRevocationList::getX509Crl() const
{
	return this->crl;
}

std::vector<Extension*> CertificateRevocationList::getExtension(Extension::Name extensionName) const
{
	std::vector<Extension *> ret;
	int next = X509_CRL_get_ext_count(this->crl);
	for (int i = 0; i < next; i++) {
		X509_EXTENSION *ext = X509_CRL_get_ext(this->crl, i);
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
	int next = X509_CRL_get_ext_count(this->crl);
	for (int i = 0; i < next; i++) {
		X509_EXTENSION *ext = X509_CRL_get_ext(this->crl, i);
		Extension *oneExt = ExtensionFactory::getExtension(ext);
		ret.push_back(oneExt);
	}
	return ret;
}

std::vector<Extension*> CertificateRevocationList::getUnknownExtensions() const
{
	Extension *oneExt = NULL;
	std::vector<Extension*> ret;
	int next = X509_CRL_get_ext_count(this->crl);
	for (int i = 0; i < next; i++) {
		X509_EXTENSION *ext = X509_CRL_get_ext(this->crl, i);
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
