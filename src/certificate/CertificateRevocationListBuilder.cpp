#include <libcryptosec/certificate/CertificateRevocationListBuilder.h>

#include <libcryptosec/certificate/extension/ExtensionFactory.h>
#include <libcryptosec/asymmetric/PrivateKey.h>
#include <libcryptosec/ByteArray.h>
#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/DecodeException.h>
#include <libcryptosec/exception/EncodeException.h>

#include <openssl/pem.h>

#include <string>
#include <vector>

CertificateRevocationListBuilder::CertificateRevocationListBuilder() :
		CertificateRevocationList(X509_CRL_new())
{
	THROW_ENCODE_ERROR_IF(this->crl == NULL);
	try {
		DateTime dateTime;
		this->setLastUpdate(dateTime);
		this->setNextUpdate(dateTime);
	} catch (...) {
		X509_CRL_free(this->crl);
		throw;
	}
}

CertificateRevocationListBuilder::CertificateRevocationListBuilder(const std::string& pemEncoded) :
		CertificateRevocationList(pemEncoded)
{
}

CertificateRevocationListBuilder::CertificateRevocationListBuilder(const ByteArray& derEncoded) :
		CertificateRevocationList(derEncoded)
{
}

CertificateRevocationListBuilder::~CertificateRevocationListBuilder()
{
}

void CertificateRevocationListBuilder::setSerialNumber(long serial)
{
	int rc = 0;

	ASN1_INTEGER *serialAsn1 = ASN1_INTEGER_new();
	THROW_ENCODE_ERROR_IF(serialAsn1 == NULL);

	rc = ASN1_INTEGER_set(serialAsn1, serial);
	THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
			ASN1_INTEGER_free(serialAsn1);
	);

	rc = X509_CRL_add1_ext_i2d(this->crl, NID_crl_number, serialAsn1, 0, 0);
	ASN1_INTEGER_free(serialAsn1);
	THROW_ENCODE_ERROR_IF(rc == 0);
}

void CertificateRevocationListBuilder::setSerialNumber(const BigInteger& serial)
{
	ASN1_INTEGER *asn1Int = serial.getASN1Value();
	int rc = X509_CRL_add1_ext_i2d(this->crl, NID_crl_number, asn1Int, 0, 0);
	ASN1_INTEGER_free(asn1Int);
	THROW_ENCODE_ERROR_IF(rc == 0);
}

void CertificateRevocationListBuilder::setVersion(long version)
{
	int rc = X509_CRL_set_version(this->crl, version);
	THROW_ENCODE_ERROR_IF(rc == 0);
}

void CertificateRevocationListBuilder::setIssuer(const RDNSequence& issuer)
{
	X509_NAME *name = issuer.getSslObject();
	int rc = X509_CRL_set_issuer_name(this->crl, name);
	X509_NAME_free(name);
	THROW_ENCODE_ERROR_IF(rc == 0);
}

void CertificateRevocationListBuilder::setIssuer(const X509* issuer)
{
	const X509_NAME *sslName = X509_get_subject_name(issuer);
	int rc = X509_CRL_set_issuer_name(this->crl, (X509_NAME*) sslName);
	THROW_ENCODE_ERROR_IF(rc == 0);
}

void CertificateRevocationListBuilder::setLastUpdate(const DateTime& dateTime)
{
	/*
	 * Devido a um bug do firefox ao abrir CRL com datas em formato GeneralizedTime, mudou-se para UTC
	 * */
	//asn1Time = dateTime.getAsn1Time();
	ASN1_TIME *asn1Time = dateTime.getUTCTime();
	int rc = X509_CRL_set_lastUpdate(this->crl, asn1Time);
	ASN1_TIME_free(asn1Time);
	THROW_ENCODE_ERROR_IF(rc == 0);
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
	THROW_ENCODE_ERROR_IF(rc == 0);
}

void CertificateRevocationListBuilder::addRevokedCertificate(const RevokedCertificate& revoked)
{
	X509_REVOKED* sslRevoked = revoked.getSslObject();
	int rc = X509_CRL_add0_revoked(this->crl, sslRevoked);
	THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
			X509_REVOKED_free(sslRevoked);
	);
}

void CertificateRevocationListBuilder::addRevokedCertificates(const std::vector<RevokedCertificate>& revokedCertificates)
{
	for (auto revokedCertificate : revokedCertificates) {
		this->addRevokedCertificate(revokedCertificate);
	}
}

CertificateRevocationList CertificateRevocationListBuilder::sign(const PrivateKey& privateKey, MessageDigest::Algorithm messageDigestAlgorithm)
{
	int rc = 0;

	int extensionCount = X509_CRL_get_ext_count(this->crl);

	// Se o certificado tiver extensões, a versão deve
	// ser 2, representada pelo valor 1
	if (extensionCount > 0){
		this->setVersion(1);
	} else {
		this->setVersion(0);
	}

	const EVP_PKEY *pkey = privateKey.getEvpPkey();
	const EVP_MD *md = MessageDigest::getMessageDigest(messageDigestAlgorithm);
	rc = X509_CRL_sign(this->crl, (EVP_PKEY*) pkey, md);
	THROW_ENCODE_ERROR_IF(rc == 0);

    CertificateRevocationList ret((const X509_CRL*) this->crl);

    X509_CRL_free(this->crl);
    this->crl = X509_CRL_new();
	THROW_ENCODE_ERROR_IF(this->crl == NULL);
	try {
		DateTime dateTime;
		this->setLastUpdate(dateTime);
		this->setNextUpdate(dateTime);
	} catch (...) {
		X509_CRL_free(this->crl);
		throw;
	}

    return ret;
}

void CertificateRevocationListBuilder::addExtension(const Extension& extension)
{	
	X509_EXTENSION *ext = extension.getX509Extension();
	int rc = X509_CRL_add_ext(this->crl, ext, -1);
	X509_EXTENSION_free(ext);
	THROW_ENCODE_ERROR_IF(rc == 0);
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
	ASN1_OBJECT *sslOid = oid.getSslObject();
	int position = X509_CRL_get_ext_by_OBJ(this->crl, sslOid, -1);
	ASN1_OBJECT_free(sslOid);
	if (position >= 0) {
		X509_EXTENSION *ext = X509_CRL_delete_ext(this->crl, position);
		THROW_ENCODE_ERROR_IF(ext == NULL);
		X509_EXTENSION_free(ext);
	}
	this->addExtension(extension);
}
