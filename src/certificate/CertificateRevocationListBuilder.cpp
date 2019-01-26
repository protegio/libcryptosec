#include <libcryptosec/certificate/CertificateRevocationListBuilder.h>

#include <libcryptosec/exception/EncodeException.h>

#include <libcryptosec/certificate/extension/ExtensionFactory.h>
#include <libcryptosec/PrivateKey.h>
#include <libcryptosec/ByteArray.h>
#include <libcryptosec/exception/AsymmetricKeyException.h>
#include <libcryptosec/exception/CertificationException.h>

#include <openssl/pem.h>

#include <string>
#include <vector>

CertificateRevocationListBuilder::CertificateRevocationListBuilder() :
		crl(X509_CRL_new())
{
	if (!this->crl) {
		throw CertificationException(CertificationException::X509_CRL_NEW_ERROR, "CertificateRevocationListBuilder::CertificateRevocationListBuilder");
	}
	DateTime dateTime;
	this->setLastUpdate(dateTime);
	this->setNextUpdate(dateTime);
}

CertificateRevocationListBuilder::CertificateRevocationListBuilder(const std::string& pemEncoded)
{
	BIO *buffer = NULL;
	unsigned int numberOfBytes = 0;

	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL) {
		throw EncodeException(EncodeException::BUFFER_CREATING, "CertificateRevocationListBuilder::CertificateRevocationListBuilder");
	}

	numberOfBytes = BIO_write(buffer, pemEncoded.c_str(), pemEncoded.size());
	if (numberOfBytes != pemEncoded.size()) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "CertificateRevocationListBuilder::CertificateRevocationListBuilder");
	}

	this->crl = PEM_read_bio_X509_CRL(buffer, NULL, NULL, NULL);
	if (this->crl == NULL) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_DECODE, "CertificateRevocationListBuilder::CertificateRevocationListBuilder");
	}

	BIO_free(buffer);
}

CertificateRevocationListBuilder::CertificateRevocationListBuilder(const ByteArray& derEncoded)
{
	BIO *buffer = NULL;
	unsigned int numberOfBytes = 0;

	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL) {
		throw EncodeException(EncodeException::BUFFER_CREATING, "CertificateRevocationListBuilder::CertificateRevocationListBuilder");
	}

	numberOfBytes = BIO_write(buffer, derEncoded.getConstDataPointer(), derEncoded.getSize());
	if (numberOfBytes != derEncoded.getSize()) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "CertificateRevocationListBuilder::CertificateRevocationListBuilder");
	}

	this->crl = d2i_X509_CRL_bio(buffer, NULL); /* TODO: will the second parameter work fine ? */
	if (this->crl == NULL) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_DECODE, "CertificateRevocationListBuilder::CertificateRevocationListBuilder");
	}

	BIO_free(buffer);
}

CertificateRevocationListBuilder::CertificateRevocationListBuilder(const CertificateRevocationListBuilder& crl) :
		crl(X509_CRL_dup(crl.crl))
{
	if (this->crl == NULL) {
		throw CertificationException(CertificationException::X509_CRL_DUP_ERROR, "CertificateRevocationListBuilder::CertificateRevocationListBuilder");
	}
}

CertificateRevocationListBuilder::CertificateRevocationListBuilder(CertificateRevocationListBuilder&& crl) :
		crl(crl.crl)
{
	crl.crl = nullptr;
}

CertificateRevocationListBuilder::~CertificateRevocationListBuilder()
{
	if (this->crl) {
		X509_CRL_free(this->crl);
	}
}

CertificateRevocationListBuilder& CertificateRevocationListBuilder::operator=(const CertificateRevocationListBuilder& value)
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


std::string CertificateRevocationListBuilder::getXmlEncoded(const std::string& tab) const
{
	std::string ret;
	char temp[11];
	std::vector<RevokedCertificate> revokedCertificates;
	unsigned int i;
	ret = tab + "<certificateRevocationList>\n";
	
	ret = tab + "\t<tbsCertList>\n";
		
		try /* version */
		{
			sprintf(temp, "%d", (int)this->getVersion());
			ret += tab + "\t\t<version>" + temp + "</version>\n";
		}
		catch (...)
		{
		}
		try /* Serial Number */
		{
			sprintf(temp, "%d", (int)this->getSerialNumber());
			ret += tab + "\t\t<serialNumber>" + temp + "</serialNumber>\n";
		}
		catch (...)
		{
		}
		ret += tab + "\t\t<issuer>\n";

				ret += (this->getIssuer()).getXmlEncoded("\t\t\t");

		ret += tab + "\t\t</issuer>\n";

		ret += tab + "\t\t<lastUpdate>" + this->getLastUpdate().getXmlEncoded() + "</lastUpdate>";

		ret += tab + "\t\t<nextUpdate>" + this->getNextUpdate().getXmlEncoded() + "</nextUpdate>";
		
		ret += tab + "\t\t<revokedCertificates>\n";
			revokedCertificates = this->getRevokedCertificates();
			for (i=0;i<revokedCertificates.size();i++)
			{
				ret += revokedCertificates.at(i).getXmlEncoded(tab + "\t\t\t");
			}
		ret += tab + "\t\t</revokedCertificates>\n";

	ret = tab + "\t</tbsCertList>\n";
	
	ret += tab + "</certificateRevocationList>\n";
	return ret;
}

void CertificateRevocationListBuilder::setSerialNumber(long serial)
{
	ASN1_INTEGER* serialAsn1;
	int rc;
	serialAsn1 = ASN1_INTEGER_new();
	ASN1_INTEGER_set(serialAsn1, serial);
	rc = X509_CRL_add1_ext_i2d(this->crl, NID_crl_number, serialAsn1, 0, 0);
	ASN1_INTEGER_free(serialAsn1);
	if (rc != 1)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationListBuilder::setSerialNumber");
	}
}

void CertificateRevocationListBuilder::setSerialNumber(const BigInteger& serial)
{
	int rc = X509_CRL_add1_ext_i2d(this->crl, NID_crl_number, serial.getASN1Value(), 0, 0);
	if (rc != 1) {
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationListBuilder::setSerialNumber");
	}
}

long CertificateRevocationListBuilder::getSerialNumber() const
{
	ASN1_INTEGER* asn1Integer = this->getSerialNumberAsn1();
	// TODO: essa verificação de erro está correta? outros lugares usam a mesma coisa
	long ret = ASN1_INTEGER_get(asn1Integer);
	if (ret < 0L) {
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationListBuilder::getSerialNumber");
	}
	ASN1_INTEGER_free(asn1Integer);
	return ret;
}

BigInteger CertificateRevocationListBuilder::getSerialNumberBigInt() const
{
	ASN1_INTEGER* asn1Integer = this->getSerialNumberAsn1();
	BigInteger ret(asn1Integer);
	ASN1_INTEGER_free(asn1Integer);
	return std::move(ret);
}

ASN1_INTEGER* CertificateRevocationListBuilder::getSerialNumberAsn1() const {
	ASN1_INTEGER *asn1Int = NULL;
	if (this->crl == NULL) {
		throw CertificationException(CertificationException::INVALID_CRL, "CertificateRevocationListBuilder::getSerialNumber");
	}

	asn1Int = (ASN1_INTEGER*) X509_CRL_get_ext_d2i(this->crl, NID_crl_number, 0, 0);
	if (asn1Int == NULL || asn1Int->data == NULL) {
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateRevocationListBuilder::getSerialNumber");
	}

	return asn1Int;
}

void CertificateRevocationListBuilder::setVersion(long version)
{
	int rc = X509_CRL_set_version(this->crl, version);
	if (rc == 0) {
		throw CertificationException(CertificationException::X509_CRL_SET_VERSION_ERROR, "CertificateRevocationListBuilder::setVersion(long)");
	}
}

long CertificateRevocationListBuilder::getVersion() const
{
	long ret = 0;

	// TODO: A verificação vai falhar em versões mais novas ou alternativas do X509
	ret = X509_CRL_get_version(this->crl);
	if (ret < 0 || ret > 1) {
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateRevocationListBuilder::getVersion");
	}

	return ret;
}

void CertificateRevocationListBuilder::setIssuer(const RDNSequence& issuer)
{
	X509_NAME *name = issuer.getX509Name();
	int rc = X509_CRL_set_issuer_name(this->crl, name);
	X509_NAME_free(name);
	if (!rc) {
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationListBuilder::setIssuer");
	}
}

void CertificateRevocationListBuilder::setIssuer(X509* issuer)
{
	//TODO(lucasperin):
	int rc;
	//      X509_NAME *name;
	//      name = issuer.getX509Name();
	rc = X509_CRL_set_issuer_name(this->crl, X509_get_subject_name(issuer));
	//      X509_NAME_free(name);
	if (!rc)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationListBuilder::setIssuer");
	}
}

RDNSequence CertificateRevocationListBuilder::getIssuer() const
{
	X509_NAME* name = X509_CRL_get_issuer(this->crl);
	if (name == NULL) {
		throw CertificationException(CertificationException::X509_CRL_GET_ISSUER_ERROR, "CertificateRevocationListBuilder::getIssuer()");
	}
	return RDNSequence(name);
}

void CertificateRevocationListBuilder::setLastUpdate(const DateTime& dateTime)
{
	ASN1_TIME *asn1Time;
	
	/*
	 * Devido a um bug do firefox ao abrir CRL com datas em formato GeneralizedTime, mudou-se para UTC
	 * */
	//asn1Time = dateTime.getAsn1Time();
	asn1Time = dateTime.getUTCTime();
	X509_CRL_set_lastUpdate(this->crl, asn1Time);
	ASN1_TIME_free(asn1Time);
}

DateTime CertificateRevocationListBuilder::getLastUpdate() const
{
	const ASN1_TIME* dateTime = X509_CRL_get0_lastUpdate(this->crl);
	if (dateTime == NULL) {
		throw CertificationException("" /* TODO */);
	}
	return DateTime(dateTime);
}

void CertificateRevocationListBuilder::setNextUpdate(const DateTime& dateTime)
{
	/*
	 * Devido a um bug do firefox ao abrir CRL com datas em formato GeneralizedTime,
	 * mudou-se para UTC
	 * */
	ASN1_TIME *dateAsn1 = dateTime.getAsn1Time();
	int rc = X509_CRL_set_nextUpdate(this->crl, dateAsn1);
	ASN1_TIME_free(dateAsn1);
	if (rc == 0) {
		throw CertificationException("" /* TODO */);
	}
}

DateTime CertificateRevocationListBuilder::getNextUpdate() const
{
	const ASN1_TIME* dateTime = X509_CRL_get0_nextUpdate(this->crl);
	if (dateTime == NULL) {
		throw CertificationException("" /* TODO */);
	}
	return DateTime(dateTime);
}

void CertificateRevocationListBuilder::addRevokedCertificate(const RevokedCertificate& revoked)
{
	X509_REVOKED* sslRevoked = revoked.getX509Revoked();
	int rc = X509_CRL_add0_revoked(this->crl, sslRevoked);
	if (!rc) {
		X509_REVOKED_free(sslRevoked);
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationListBuilder::addRevokedCertificate");
    }
}

void CertificateRevocationListBuilder::addRevokedCertificates(const std::vector<RevokedCertificate>& revokedCertificates)
{
	for (auto revokedCertificate : revokedCertificates) {
		this->addRevokedCertificate(revokedCertificate);
	}
}

std::vector<RevokedCertificate> CertificateRevocationListBuilder::getRevokedCertificates() const
{
	std::vector<RevokedCertificate> ret;
    STACK_OF(X509_REVOKED)* revokedStack = NULL;
    X509_REVOKED *revoked = NULL;
    int size = 0;

    revokedStack = X509_CRL_get_REVOKED(this->crl);
    if (revokedStack == NULL) {
    	throw CertificationException("" /* TODO */);
    }

    size = sk_X509_REVOKED_num(revokedStack);
    for (int i = 0; i < size; i++) {
    	revoked = sk_X509_REVOKED_value(revokedStack, i);
    	if (revoked == NULL) {
    		throw CertificationException("" /* TODO */);
    	}
    	ret.push_back(RevokedCertificate(revoked));
    	// TODO: temos que desalocar o certificado revogado?
    }

    return ret;
}

CertificateRevocationList CertificateRevocationListBuilder::sign(
		const PrivateKey& privateKey, MessageDigest::Algorithm messageDigestAlgorithm)
{
	int rc = 0;

	// Define vesion
	if (X509_CRL_get_ext_count(this->crl)) {
		this->setVersion(1);
	} else {
		this->setVersion(0);
	}

	// TODO: esse cast é ok?
	rc = X509_CRL_sign(this->crl, (EVP_PKEY*) privateKey.getEvpPkey(),
			MessageDigest::getMessageDigest(messageDigestAlgorithm));
	if (rc == 0) {
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationListBuilder::sign");
    }

    return CertificateRevocationList((const X509_CRL*) this->crl);
}

const X509_CRL* CertificateRevocationListBuilder::getX509Crl() const
{
	return this->crl;
}

void CertificateRevocationListBuilder::addExtension(const Extension& extension)
{	
	X509_EXTENSION *ext = extension.getX509Extension();
	int rc = X509_CRL_add_ext(this->crl, ext, -1);
	if (!rc) {
		X509_EXTENSION_free(ext);
		throw CertificationException(CertificationException::ADDING_EXTENSION, "CertificateRevocationListBuilder::addExtension");
	}
}

void CertificateRevocationListBuilder::addExtensions(const std::vector<Extension*>& extensions)
{
	for (auto extension : extensions) {
		this->addExtension(*extension);
	}
}

void CertificateRevocationListBuilder::replaceExtension(const Extension& extension)
{
	ObjectIdentifier oid = extension.getObjectIdentifier();
	int position = X509_CRL_get_ext_by_OBJ(this->crl, oid.getObjectIdentifier(), -1);
	if (position >= 0) {
		X509_EXTENSION *ext = X509_CRL_delete_ext(this->crl, position);
		X509_EXTENSION_free(ext);
	}
	this->addExtension(extension);
}

std::vector<Extension*> CertificateRevocationListBuilder::getExtension(Extension::Name extensionName) const
{
	Extension *oneExt = NULL;
	std::vector<Extension*> ret;
	X509_EXTENSION *ext = NULL;
	int next = 0;

	next = X509_CRL_get_ext_count(this->crl);
	for (int i = 0; i < next; i++) {
		ext = X509_CRL_get_ext(this->crl, i);
		if (Extension::getName(ext) == extensionName) {
			oneExt = ExtensionFactory::getExtension(ext);
			ret.push_back(oneExt);
		}
	}
	return ret;
}

//Martin: 26/09/07
std::vector<Extension*> CertificateRevocationListBuilder::getExtensions() const
{
	Extension *oneExt = NULL;
	std::vector<Extension*> ret;
	X509_EXTENSION *ext = NULL;
	int next = 0;

	next = X509_CRL_get_ext_count(this->crl);
	for (int i = 0; i < next; i++) {
		ext = X509_CRL_get_ext(this->crl, i);
		oneExt = ExtensionFactory::getExtension(ext);
		ret.push_back(oneExt);
	}
	return ret;
}

//Martin: 26/09/07
std::vector<Extension*> CertificateRevocationListBuilder::getUnknownExtensions() const
{
	Extension *oneExt = NULL;
	std::vector<Extension*> ret;
	X509_EXTENSION *ext = NULL;
	int next = 0;

	next = X509_CRL_get_ext_count(this->crl);
	for (int i = 0; i < next; i++) {
		ext = X509_CRL_get_ext(this->crl, i);
		switch (Extension::getName(ext))
		{
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
