#include <libcryptosec/certificate/Certificate.h>

#include <libcryptosec/certificate/CertificateRequest.h>
#include <libcryptosec/certificate/RDNSequence.h>
#include <libcryptosec/certificate/extension/Extension.h>
#include <libcryptosec/certificate/extension/ExtensionFactory.h>
#include <libcryptosec/PrivateKey.h>
#include <libcryptosec/PublicKey.h>
#include <libcryptosec/DateTime.h>
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/ByteArray.h>
#include <libcryptosec/Base64.h>
#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/CertificationException.h>
#include <libcryptosec/exception/EncodeException.h>

#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <vector>
#include <string>

#include <time.h>

Certificate::Certificate(X509* cert) :
		cert(cert)
{
}

Certificate::Certificate(const X509* cert) :
		cert(X509_dup((X509*) cert))
{
	THROW_DECODE_ERROR_IF(this->cert == NULL);
}

Certificate::Certificate(const std::string& pemEncoded)
{
	DECODE_PEM(this->cert, pemEncoded, PEM_read_bio_X509);
}

Certificate::Certificate(const ByteArray& derEncoded)
{
	DECODE_DER(this->cert, derEncoded, d2i_X509_bio);
}

Certificate::Certificate(const Certificate& cert) :
		cert(X509_dup(cert.cert))
{
	THROW_DECODE_ERROR_IF(this->cert == NULL);
}

Certificate::Certificate(Certificate&& cert)
	: cert(cert.cert)
{
	THROW_DECODE_ERROR_IF(this->cert == NULL);
	cert.cert = nullptr;
}

Certificate::~Certificate()
{
	if (this->cert) {
		X509_free(this->cert);
	}
}

Certificate& Certificate::operator=(const Certificate& value)
{
	if (&value == this) {
		return *this;
	}

	if (this->cert) {
		X509_free(this->cert);
	}

	this->cert = X509_dup(value.cert);

	THROW_DECODE_ERROR_IF(this->cert == NULL);

    return *this;
}

Certificate& Certificate::operator=(Certificate&& value)
{
	if (&value == this) {
		return *this;
	}

	if (this->cert) {
		X509_free(this->cert);
	}

	this->cert = value.cert;
	value.cert = nullptr;

	THROW_DECODE_ERROR_IF(this->cert == NULL);

    return *this;
}

long int Certificate::getSerialNumber() const
{
	/* Here, we have a problem!!! the return value -1 can be error and a valid value. */
	ASN1_INTEGER *asn1Int = X509_get_serialNumber(this->cert);
	THROW_DECODE_ERROR_IF(asn1Int == NULL);
	THROW_DECODE_ERROR_IF(asn1Int->data == NULL);

	long ret = ASN1_INTEGER_get(asn1Int);
	THROW_DECODE_ERROR_IF(ret < 0L);

	return ret;
}

BigInteger Certificate::getSerialNumberBigInt() const
{
	/* Here, we have a problem!!! the return value -1 can be error and a valid value. */
	const ASN1_INTEGER *asn1Int = X509_get_serialNumber(this->cert);
	THROW_DECODE_ERROR_IF(asn1Int == NULL);
	THROW_DECODE_ERROR_IF(asn1Int->data == NULL);

	BigInteger ret(asn1Int);
	return ret;
}

MessageDigest::Algorithm Certificate::getMessageDigestAlgorithm() const
{
	// Não verificamos o erro pois getMessageDigest já lança exceção se o nid for inválido
	int nid = X509_get_signature_nid(this->cert);
	MessageDigest::Algorithm ret = MessageDigest::getMessageDigest(nid);
	return ret;
}

PublicKey Certificate::getPublicKey() const
{
	const EVP_PKEY *key = X509_get0_pubkey(this->cert);
	THROW_DECODE_ERROR_IF(key == NULL);
	PublicKey ret(key);
	return ret;
}

ByteArray Certificate::getPublicKeyInfo() const
{
	const ASN1_BIT_STRING *pubKeyBits = X509_get0_pubkey_bitstr(this->cert);
	THROW_DECODE_ERROR_IF(pubKeyBits == NULL);
	MessageDigest md(MessageDigest::SHA1);
	ByteArray ret = md.doFinal(pubKeyBits->data, pubKeyBits->length);
	return ret;
}

long Certificate::getVersion() const
{
	/* Here, we have a problem!!! the return value 0 can be error and a valid value. */
	long ret = X509_get_version(this->cert);
	THROW_DECODE_ERROR_IF(ret < 0 || ret > 2);
	return ret;
}

DateTime Certificate::getNotBefore() const
{
	const ASN1_TIME *asn1Time = X509_get0_notBefore(this->cert);
	THROW_DECODE_ERROR_IF(asn1Time == NULL);
	DateTime ret(asn1Time);
	return ret;
}

DateTime Certificate::getNotAfter() const
{
	const ASN1_TIME *asn1Time = X509_get0_notAfter(this->cert);
	THROW_DECODE_ERROR_IF(asn1Time == NULL);
	DateTime ret(asn1Time);
	return ret;
}

RDNSequence Certificate::getIssuer() const
{
	const X509_NAME *issuer = X509_get_issuer_name(this->cert);
	THROW_DECODE_ERROR_IF(issuer == NULL);
	RDNSequence name(issuer);
	return name;
}

RDNSequence Certificate::getSubject() const
{
	const X509_NAME *issuer = X509_get_subject_name(this->cert);
	THROW_DECODE_ERROR_IF(issuer == NULL);
	RDNSequence name(issuer);
	return name;
}

std::vector<Extension*> Certificate::getExtension(Extension::Name extensionName) const
{
	std::vector<Extension*> ret;
	int num = X509_get_ext_count(this->cert);
	for (int i = 0; i < num; i++) {
		const X509_EXTENSION *ext = X509_get_ext(this->cert, i);
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

std::vector<Extension*> Certificate::getExtensions() const
{
	std::vector<Extension*> ret;
	int num = X509_get_ext_count(this->cert);
	for (int i = 0; i < num; i++) {
		const X509_EXTENSION *ext = X509_get_ext(this->cert, i);
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

std::vector<Extension*> Certificate::getUnknownExtensions() const
{
	std::vector<Extension*> ret;
	Extension *oneExt = NULL;
	int num = X509_get_ext_count(this->cert);
	for (int i = 0; i < num; i++) {
		const X509_EXTENSION *ext = X509_get_ext(this->cert, i);
		THROW_DECODE_ERROR_AND_FREE_IF(ext == NULL,
				for (auto extension : ret) {
					delete extension;
				}
		);
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

ByteArray Certificate::getFingerPrint(MessageDigest::Algorithm algorithm) const
{
	MessageDigest messageDigest(algorithm);
	ByteArray derEncoded = this->getDerEncoded();
	ByteArray ret = messageDigest.doFinal(std::move(derEncoded));
	return ret;
}

bool Certificate::verify(const PublicKey& publicKey) const
{
	// TODO: cast ok?
	int ok = X509_verify(this->cert, (EVP_PKEY*) publicKey.getEvpPkey());
	return (ok == 1);
}

CertificateRequest Certificate::getNewCertificateRequest(const PrivateKey &privateKey, MessageDigest::Algorithm algorithm) const
{
	const EVP_MD *md = MessageDigest::getMessageDigest(algorithm);

	// TODO: cast ok?
	X509_REQ *sslReq = X509_to_X509_REQ(this->cert, (EVP_PKEY*) privateKey.getEvpPkey(), md);

	// TODO: check exception type
	THROW_IF(sslReq == NULL, CertificationException, CertificationException::INTERNAL_ERROR);
	CertificateRequest req((const X509_REQ*) sslReq);
	X509_REQ_free(sslReq);

	return req;
}

bool Certificate::operator==(const Certificate& value)
{
	int result = X509_cmp(this->cert, value.cert);
	return result == 0;
}

bool Certificate::operator!=(const Certificate& value)
{
	return !this->operator==(value);
}

std::string Certificate::getPemEncoded() const
{
	ENCODE_PEM_AND_RETURN(this->cert, PEM_write_bio_X509);
}

ByteArray Certificate::getDerEncoded() const
{
	ENCODE_DER_AND_RETURN(this->cert, i2d_X509_bio);
}

// TODO: use X509_check_private_key(cert, pkey)

std::string Certificate::toXml(const std::string& tab) const
{
	std::string ret, string;
	ByteArray data;
	char temp[15];
	long value;
	std::vector<Extension *> extensions;
	unsigned int i;

	ret = "<?xml version=\"1.0\"?>\n";
	ret += "<certificate>\n";
	ret += "\t<tbsCertificate>\n";
		try /* version */
		{
			value = this->getVersion();
			sprintf(temp, "%d", (int)value);
			string = temp;
			ret += "\t\t<version>" + string + "</version>\n";
		}
		catch (...)
		{
		}
		try /* Serial Number */
		{
			ret += "\t\t<serialNumber>" + this->getSerialNumberBigInt().toDec() + "</serialNumber>\n";
		}
		catch (...)
		{
		}
		string = OBJ_nid2ln(X509_get_signature_nid(this->cert));
		ret += "\t\t<signature>" + string + "</signature>\n";

		ret += "\t\t<issuer>\n";
			try
			{
				ret += (this->getIssuer()).toXml("\t\t\t");
			}
			catch (...)
			{
			}
		ret += "\t\t</issuer>\n";

		ret += "\t\t<validity>\n";
			try
			{
				ret += "\t\t\t<notBefore>" + ((this->getNotBefore()).toXml()) + "</notBefore>\n";
			}
			catch (...)
			{
			}
			try
			{
				ret += "\t\t\t<notAfter>" + ((this->getNotAfter()).toXml()) + "</notAfter>\n";
			}
			catch (...)
			{
			}
		ret += "\t\t</validity>\n";

		ret += "\t\t<subject>\n";
			try
			{
				ret += (this->getSubject()).toXml("\t\t\t");
			}
			catch (...)
			{
			}
		ret += "\t\t</subject>\n";

		ret += "\t\t<subjectPublicKeyInfo>\n";

			string = OBJ_nid2ln(EVP_PKEY_id(X509_get0_pubkey(this->cert)));
			ret += "\t\t\t<algorithm>" + string + "</algorithm>\n";

			const ASN1_BIT_STRING* public_key = X509_get0_pubkey_bitstr(this->cert);
			data = ByteArray(public_key->data, public_key->length);
			string = Base64::encode(data);
			ret += "\t\t\t<subjectPublicKey>" + string + "</subjectPublicKey>\n";
		ret += "\t\t</subjectPublicKeyInfo>\n";

		const ASN1_BIT_STRING *issuerUID, *subjectUID;
		X509_get0_uids(this->cert, &subjectUID, &issuerUID);

		if (issuerUID)
		{
			data = ByteArray(issuerUID->data, issuerUID->length);
			string = Base64::encode(data);
			ret += "\t\t<issuerUniqueID>" + string + "</issuerUniqueID>\n";
		}

		if (subjectUID)
		{
			data = ByteArray(subjectUID->data, subjectUID->length);
			string = Base64::encode(data);
			ret += "\t\t<subjectUniqueID>" + string + "</subjectUniqueID>\n";
		}

		ret += "\t\t<extensions>\n";
		extensions = this->getExtensions();
		for (i=0;i<extensions.size();i++)
		{
			ret += extensions.at(i)->toXml("\t\t\t");
			delete extensions.at(i);
		}
		ret += "\t\t</extensions>\n";

	ret += "\t</tbsCertificate>\n";

	ret += "\t<signatureAlgorithm>\n";
		string = OBJ_nid2ln(X509_get_signature_nid(this->cert));
		ret += "\t\t<algorithm>" + string + "</algorithm>\n";
	ret += "\t</signatureAlgorithm>\n";

	const ASN1_BIT_STRING* signature = 0;
	X509_get0_signature(&signature, 0, this->cert);
	data = ByteArray(signature->data, signature->length);
	string = Base64::encode(data);
	ret += "\t<signatureValue>" + string + "</signatureValue>\n";

	ret += "</certificate>\n";
	return ret;

}

X509* Certificate::getSslObject() const
{
	X509 *sslObject = X509_dup(this->cert);
	THROW_DECODE_ERROR_IF(sslObject == NULL);
	return sslObject;
}

const X509* Certificate::getX509() const
{
	return this->cert;
}
