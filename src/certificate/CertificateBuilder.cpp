#include <libcryptosec/certificate/CertificateBuilder.h>

#include <libcryptosec/certificate/Certificate.h>
#include <libcryptosec/certificate/CertificateRequest.h>
#include <libcryptosec/certificate/Extension.h>
#include <libcryptosec/certificate/ExtensionFactory.h>
#include <libcryptosec/certificate/KeyUsageExtension.h>
#include <libcryptosec/certificate/ExtendedKeyUsageExtension.h>
#include <libcryptosec/certificate/BasicConstraintsExtension.h>
#include <libcryptosec/certificate/CRLDistributionPointsExtension.h>
#include <libcryptosec/certificate/IssuerAlternativeNameExtension.h>
#include <libcryptosec/certificate/SubjectAlternativeNameExtension.h>
#include <libcryptosec/certificate/SubjectInformationAccessExtension.h>
#include <libcryptosec/certificate/AuthorityKeyIdentifierExtension.h>
#include <libcryptosec/certificate/SubjectKeyIdentifierExtension.h>
#include <libcryptosec/certificate/CertificatePoliciesExtension.h>
#include <libcryptosec/exception/AsymmetricKeyException.h>
#include <libcryptosec/exception/CertificationException.h>
#include <libcryptosec/exception/EncodeException.h>
#include <libcryptosec/PrivateKey.h>
#include <libcryptosec/PublicKey.h>
#include <libcryptosec/DateTime.h>
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/ByteArray.h>

CertificateBuilder::CertificateBuilder()
	: cert(X509_new()), includeECDSAParameters(false)
{
	DateTime dateTime;
	this->setNotBefore(dateTime);
	this->setNotAfter(dateTime);
}

CertificateBuilder::CertificateBuilder(const std::string& pemEncoded)
	: includeECDSAParameters(false)
{
	BIO *buffer = NULL;
	unsigned int numberOfBytesWritten = 0;

	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL) {
		throw EncodeException(EncodeException::BUFFER_CREATING, "CertificateBuilder::CertificateBuilder");
	}

	numberOfBytesWritten = BIO_write(buffer, pemEncoded.c_str(), pemEncoded.size());
	if (numberOfBytesWritten != pemEncoded.size()) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "CertificateBuilder::CertificateBuilder");
	}

	this->cert = PEM_read_bio_X509(buffer, NULL, NULL, NULL);
	if (this->cert == NULL) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_DECODE, "CertificateBuilder::CertificateBuilder");
	}

	BIO_free(buffer);
}

CertificateBuilder::CertificateBuilder(const ByteArray& derEncoded)
	: includeECDSAParameters(false)
{
	BIO *buffer = 0;
	unsigned int numberOfBytesWritten = 0;

	this->includeECDSAParameters = false;

	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL) {
		throw EncodeException(EncodeException::BUFFER_CREATING, "CertificateBuilder::CertificateBuilder");
	}

	numberOfBytesWritten = BIO_write(buffer, derEncoded.getConstDataPointer(), derEncoded.getSize());
	if (numberOfBytesWritten != derEncoded.getSize()) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "CertificateBuilder::CertificateBuilder");
	}

	this->cert = d2i_X509_bio(buffer, NULL); /* TODO: will the second parameter work fine ? */
	if (this->cert == NULL) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_DECODE, "CertificateBuilder::CertificateBuilder");
	}

	BIO_free(buffer);
}

CertificateBuilder::CertificateBuilder(const CertificateRequest& request)
	: includeECDSAParameters(false)
{
	PublicKey *publicKey = NULL;
	DateTime dateTime;
	std::vector<Extension*> extensions;
	unsigned int i;

	this->includeECDSAParameters = false;

	this->cert = X509_new();

	this->setNotBefore(dateTime);
	this->setNotAfter(dateTime);

	this->setSubject(request.getX509Req());

	try {
		publicKey = request.getPublicKey();
		this->setPublicKey(*publicKey);

		extensions = request.getExtensions();
		for (i=0;i<extensions.size();i++) {
			this->addExtension(*extensions.at(i));
		}
	} catch (CertificationException &ex) {
	}

	if (publicKey) {
		delete publicKey;
	}

	// TODO: Para algumas extensoes como AuthorityInformationAccess, em alguns casos
	// o delete nao esta funcionando adequadamente
	for (i = 0; i < extensions.size(); i++) {
		delete extensions.at(i);
	}
}

CertificateBuilder::CertificateBuilder(const CertificateBuilder& cert)
	: includeECDSAParameters(false)
{
	// TODO: is this cast ok?
	this->cert = X509_dup((X509*) cert.getX509());
	if (this->cert == 0) {
		throw CertificationException(CertificationException::INVALID_CERTIFICATE,
				"CertificateBuilder::CertificateBuilder");
	}
}

CertificateBuilder::CertificateBuilder(CertificateBuilder&& builder)
	: cert(builder.cert), includeECDSAParameters(builder.includeECDSAParameters)
{
	builder.cert = nullptr;
}

CertificateBuilder::~CertificateBuilder()
{
	X509_free(this->cert);
	this->cert = NULL;
}

CertificateBuilder& CertificateBuilder::operator=(const CertificateBuilder& builder)
{
	if (&builder == this) {
		return *this;
	}

	if (this->cert) {
		X509_free(this->cert);
	}

	// TODO: Is this cast safe?
    this->cert = X509_dup((X509*) builder.getX509());
    this->includeECDSAParameters = builder.includeECDSAParameters;

    return *this;
}

// Move assignment
// Transfer ownership of a.m_ptr to m_ptr
CertificateBuilder& CertificateBuilder::operator=(CertificateBuilder&& builder)
{
	if (&builder == this)
		return *this;

	if (this->cert) {
		X509_free(this->cert);
	}

	this->cert = builder.cert;
	builder.cert = nullptr;

	return *this;
}

std::string CertificateBuilder::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string CertificateBuilder::getXmlEncoded(const std::string& tab)
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
			value = this->getSerialNumber();
			sprintf(temp, "%d", (int)value);
			string = temp;
			ret += "\t\t<serialNumber>" + string + "</serialNumber>\n";
		}
		catch (...)
		{
		}
//		string = OBJ_nid2ln(OBJ_obj2nid(this->cert->sig_alg->algorithm));
//		ret += "\t\t<signature>" + string + "</signature>\n";

		//verifica se o issuer foi definido
		if(X509_NAME_entry_count(X509_get_issuer_name(this->cert)) > 0)
		{
			ret += "\t\t<issuer>\n";
				try
				{
					ret += (this->getIssuer()).getXmlEncoded("\t\t\t");
				}
				catch (...)
				{
				}
			ret += "\t\t</issuer>\n";
		}

		ret += "\t\t<validity>\n";
			try
			{
				ret += "\t\t\t<notBefore>" + ((this->getNotBefore()).getXmlEncoded()) + "</notBefore>\n";
			}
			catch (...)
			{
			}
			try
			{
				ret += "\t\t\t<notAfter>" + ((this->getNotAfter()).getXmlEncoded()) + "</notAfter>\n";
			}
			catch (...)
			{
			}
		ret += "\t\t</validity>\n";

		ret += "\t\t<subject>\n";
			try
			{
				ret += (this->getSubject()).getXmlEncoded("\t\t\t");
			}
			catch (...)
			{
			}
		ret += "\t\t</subject>\n";

		ret += "\t\t<subjectPublicKeyInfo>\n";
			if (X509_get0_pubkey(this->cert))
			{
				string = OBJ_nid2ln(EVP_PKEY_id(X509_get0_pubkey(this->cert)));
				ret += "\t\t\t<algorithm>" + string + "</algorithm>\n";
				const ASN1_BIT_STRING* public_key = X509_get0_pubkey_bitstr(this->cert);
				data = ByteArray(public_key->data, public_key->length);
				string = Base64::encode(data);
				ret += "\t\t\t<subjectPublicKey>" + string + "</subjectPublicKey>\n";
			}
		ret += "\t\t</subjectPublicKeyInfo>\n";

		const ASN1_BIT_STRING *issuerUID, *subjectUID;
		X509_get0_uids(this->cert, &issuerUID, &subjectUID);

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
			ret += extensions.at(i)->getXmlEncoded("\t\t\t");
			delete extensions.at(i);
		}
		ret += "\t\t</extensions>\n";

	ret += "\t</tbsCertificate>\n";

//	ret += "\t<signatureAlgorithm>\n";
//		string = OBJ_nid2ln(OBJ_obj2nid(this->cert->sig_alg->algorithm));
//		ret += "\t\t<algorithm>" + string + "</algorithm>\n";
//	ret += "\t</signatureAlgorithm>\n";
//
//	data = ByteArray(this->cert->signature->data, this->cert->signature->length);
//	string = Base64::encode(data);
//	ret += "\t<signatureValue>" + string + "</signatureValue>\n";

	ret += "</certificate>\n";
	return ret;
}

std::string CertificateBuilder::toXml(const std::string& tab)
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
//		string = OBJ_nid2ln(OBJ_obj2nid(this->cert->sig_alg->algorithm));
//		ret += "\t\t<signature>" + string + "</signature>\n";

		ret += "\t\t<issuer>\n";
			try
			{
				ret += (this->getIssuer()).getXmlEncoded("\t\t\t");
			}
			catch (...)
			{
			}
		ret += "\t\t</issuer>\n";

		ret += "\t\t<validity>\n";
			try
			{
				ret += "\t\t\t<notBefore>" + ((this->getNotBefore()).getXmlEncoded()) + "</notBefore>\n";
			}
			catch (...)
			{
			}
			try
			{
				ret += "\t\t\t<notAfter>" + ((this->getNotAfter()).getXmlEncoded()) + "</notAfter>\n";
			}
			catch (...)
			{
			}
		ret += "\t\t</validity>\n";

		ret += "\t\t<subject>\n";
			try
			{
				ret += (this->getSubject()).getXmlEncoded("\t\t\t");
			}
			catch (...)
			{
			}
		ret += "\t\t</subject>\n";

		ret += "\t\t<subjectPublicKeyInfo>\n";
			if (X509_get0_pubkey(this->cert))
			{
				string = OBJ_nid2ln(EVP_PKEY_id(X509_get0_pubkey(this->cert)));
				ret += "\t\t\t<algorithm>" + string + "</algorithm>\n";

				const ASN1_BIT_STRING* public_key = X509_get0_pubkey_bitstr(this->cert);
				data = ByteArray(public_key->data, public_key->length);
				string = Base64::encode(data);
				ret += "\t\t\t<subjectPublicKey>" + string + "</subjectPublicKey>\n";
			}
		ret += "\t\t</subjectPublicKeyInfo>\n";

		const ASN1_BIT_STRING *issuerUID, *subjectUID;
		X509_get0_uids(this->cert, &issuerUID, &subjectUID);

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

//	ret += "\t<signatureAlgorithm>\n";
//		string = OBJ_nid2ln(OBJ_obj2nid(this->cert->sig_alg->algorithm));
//		ret += "\t\t<algorithm>" + string + "</algorithm>\n";
//	ret += "\t</signatureAlgorithm>\n";
//
//	data = ByteArray(this->cert->signature->data, this->cert->signature->length);
//	string = Base64::encode(data);
//	ret += "\t<signatureValue>" + string + "</signatureValue>\n";

	ret += "</certificate>\n";
	return ret;

}

std::string CertificateBuilder::getPemEncoded()
{
	BIO *buffer;
	int ndata, wrote;
	std::string ret;
	ByteArray *retTemp;
	unsigned char *data;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "CertificateBuilder::getPemEncoded");
	}
	wrote = PEM_write_bio_X509(buffer, this->cert);
	if (!wrote)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_ENCODE, "CertificateBuilder::getPemEncoded");
	}
	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "CertificateBuilder::getPemEncoded");
	}
	retTemp = new ByteArray(data, ndata);
	ret = retTemp->toString();
	delete retTemp;
	BIO_free(buffer);
	return ret;
}

ByteArray CertificateBuilder::getDerEncoded()
{
	BIO *buffer = NULL;
	unsigned char *data = NULL;
	int ndata = 0, wrote = 0;

	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL) {
		throw EncodeException(EncodeException::BUFFER_CREATING, "CertificateBuilder::getDerEncoded");
	}

	wrote = i2d_X509_bio(buffer, this->cert);
	if (!wrote) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_ENCODE, "CertificateBuilder::getDerEncoded");
	}

	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0) {
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "CertificateBuilder::getDerEncoded");
	}

	ByteArray ret(data, ndata);
	BIO_free(buffer);
	return ret;
}

void CertificateBuilder::setSerialNumber(long serial)
{
	ASN1_INTEGER* serialNumber = X509_get_serialNumber(this->cert);
	ASN1_INTEGER_set(serialNumber, serial);
}

void CertificateBuilder::setSerialNumber(const BigInteger& serial)
{
	ASN1_INTEGER* asn1Integer = serial.getASN1Value();
	X509_set_serialNumber(this->cert, asn1Integer);
	delete asn1Integer;
}

long CertificateBuilder::getSerialNumber()
{
	ASN1_INTEGER *asn1Int = 0;
	long ret = 0;

	/* Here, we have a problem!!! the return value -1 can be error and a valid value. */
	asn1Int = X509_get_serialNumber(this->cert);
	if (asn1Int == NULL) {
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateBuilder::getSerialNumber");
	}

	if (asn1Int->data == NULL) {
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::getSerialNumber");
	}

	ret = ASN1_INTEGER_get(asn1Int);
	if (ret < 0L) {
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::getSerialNumber");
	}

	return ret;
}

BigInteger CertificateBuilder::getSerialNumberBigInt()
{
	ASN1_INTEGER *asn1Int = NULL;

	/* Here, we have a problem!!! the return value -1 can be error and a valid value. */
	asn1Int = X509_get_serialNumber(this->cert);
	if (asn1Int == NULL) {
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateBuilder::getSerialNumber");
	}

	if (asn1Int->data == NULL) {
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::getSerialNumber");
	}

	return BigInteger(asn1Int);
}

MessageDigest::Algorithm CertificateBuilder::getMessageDigestAlgorithm()
{
	MessageDigest::Algorithm ret;
	int signatureNid = X509_get_signature_nid(this->cert);
	// getMessageDigest throws if signatureNid == NID_undef
	ret = MessageDigest::getMessageDigest(signatureNid);
	return ret;
}

void CertificateBuilder::setPublicKey(PublicKey& publicKey)
{
	int rc = 0;
	rc = X509_set_pubkey(this->cert, publicKey.getEvpPkey());
	if (rc == 0) {
		throw CertificationException(CertificationException::INVALID_PUBLIC_KEY, "CertificateBuilder::setPublicKey");
	}
}

PublicKey CertificateBuilder::getPublicKey()
{
	EVP_PKEY *key = NULL;

	key = X509_get_pubkey(this->cert);
	if (key == NULL) {
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateBuilder::getPublicKey");
	}

	try {
		PublicKey ret(key);
		return ret;
	} catch (...) {
		EVP_PKEY_free(key);
		throw;
	}
}

ByteArray CertificateBuilder::getPublicKeyInfo()
{
	ASN1_BIT_STRING *pubKeyBits = NULL;
	unsigned int size = 0;

	if (!X509_get_pubkey(this->cert)) {
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateBuilder::getPublicKeyInfo");
	}

	pubKeyBits = X509_get0_pubkey_bitstr(this->cert);
	ByteArray ret(EVP_MAX_MD_SIZE);

	// TODO: sempre sha1?
	EVP_Digest(pubKeyBits->data, pubKeyBits->length, ret.getDataPointer(), &size, EVP_sha1(), NULL);
	return ret;
}

void CertificateBuilder::setVersion(long version)
{
	X509_set_version(this->cert, version);
}

long CertificateBuilder::getVersion()
{
	long ret;

	if (this->cert == NULL) {
		throw CertificationException(CertificationException::INVALID_CERTIFICATE, "CertificateBuilder::getVersion");
	}

	// TODO: future or alternative versions of x509 will fail here
	ret = X509_get_version(this->cert);
	if (ret < 0 || ret > 2) {
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateBuilder::getVersion");
	}

	return ret;
}

void CertificateBuilder::setNotBefore(const DateTime &dateTime)
{
	ASN1_TIME *asn1Time = NULL;
	asn1Time = dateTime.getAsn1Time();
	X509_set1_notBefore(this->cert, asn1Time);
	ASN1_TIME_free(asn1Time);
}

DateTime CertificateBuilder::getNotBefore()
{
	const ASN1_TIME *asn1Time = NULL;
	asn1Time = X509_get0_notBefore(this->cert);
	return DateTime(asn1Time); // TODO: o constutor copia asn1Time?
}

void CertificateBuilder::setNotAfter(const DateTime &dateTime)
{
	ASN1_TIME *asn1Time = NULL;
	asn1Time = dateTime.getAsn1Time();
	X509_set1_notAfter(this->cert, asn1Time);
	ASN1_TIME_free(asn1Time);
}

DateTime CertificateBuilder::getNotAfter()
{
	const ASN1_TIME *asn1Time = 0;
	asn1Time = X509_get0_notAfter(this->cert);
	return DateTime(asn1Time); // TODO: o constutor copia asn1Time?
}

void CertificateBuilder::setIssuer(const RDNSequence &name)
{
	X509_NAME *issuer = NULL;
	issuer = name.getX509Name();
	X509_set_issuer_name(this->cert, issuer);
	X509_NAME_free(issuer);
}

void CertificateBuilder::setIssuer(X509* issuer)
{
	int rc = 0;
	X509_NAME *name = X509_get_subject_name(issuer);
	rc = X509_set_issuer_name(this->cert, name);
	if (!rc) {
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::setIssuer");
	}
}

RDNSequence CertificateBuilder::getIssuer() const
{
	X509_NAME *name = X509_get_issuer_name(this->cert);
	return RDNSequence(name); // TODO name é copiado?
}

void CertificateBuilder::alterSubject(const RDNSequence& name)
{
	X509_NAME *subject = X509_get_subject_name(this->cert);
	if(subject == NULL) {
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::alterSubject");
	}

	X509_NAME *subjectName = X509_NAME_new();
	if(subjectName == NULL) {
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::alterSubject");
	}

	std::vector<std::pair<ObjectIdentifier, std::string> > entries = name.getEntries();
	X509_NAME_ENTRY *newEntry;

	int addedFieldType = this->getCodification(name);

	std::string data;
	for(std::vector<std::pair<ObjectIdentifier, std::string> >::iterator entry = entries.begin(); entry != entries.end(); entry++)
	{
		data = entry->second;
		newEntry = X509_NAME_ENTRY_new();

		int position = X509_NAME_get_index_by_NID(subject, entry->first.getNid(), -1);

		if(!data.empty()) // If entry is not empty, add entry
		{
			if(position != -1)
			{
				X509_NAME_ENTRY* oldEntry = X509_NAME_get_entry(subject, position);

				ASN1_OBJECT* obj = X509_NAME_ENTRY_get_object(oldEntry);
				int entryType = OBJ_obj2nid(obj);

				if(!X509_NAME_ENTRY_set_object(newEntry, entry->first.getObjectIdentifier()))
				{
					throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::alterSubject");
				}

				if(!X509_NAME_ENTRY_set_data(newEntry, entryType, (unsigned char *)data.c_str(), data.length()))
				{
					throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::alterSubject");
				}

				if(!X509_NAME_add_entry(subjectName, newEntry, -1, 0))
				{
					throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::alterSubject");
				}

				X509_NAME_ENTRY_free(newEntry);

			}
			else
			{
				if(!X509_NAME_ENTRY_set_object(newEntry, entry->first.getObjectIdentifier()))
				{
					throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::alterSubject");
				}
				if(!X509_NAME_ENTRY_set_data(newEntry, addedFieldType, (unsigned char *)data.c_str(), data.length()))
				{
					throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::alterSubject");
				}
				if(!X509_NAME_add_entry(subjectName, newEntry, -1, 0))
				{
					throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::alterSubject");
				}
				X509_NAME_ENTRY_free(newEntry);
			}
		}
	}

	int rc = X509_set_subject_name(this->cert, subjectName);
	X509_NAME_free(subjectName);

	if(!rc)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::alterSubject");
	}

/*	ALTERSUBJECT VERSION 2.2.4
	X509_NAME *subject = X509_get_subject_name(this->cert);

	if(subject == NULL){
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::setSubject");
	}

	std::vector<std::pair<ObjectIdentifier, std::string> > entries = name.getEntries();

	int entryType = MBSTRING_ASC;
	for (int i=0; i<entries.size(); i++)
	{
		int pos = X509_NAME_get_index_by_OBJ(subject, entries.at(i).first.getObjectIdentifier(), -1);
		bool notCountry = entries.at(i).first.getNid() != NID_countryName;
		if (pos >= 0 && notCountry)
		{
			X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject, pos);
			entryType = entry->value->type;
			break;
		}
	}

	for (int i=0; i<entries.size(); i++)
	{
		int nameEntryPos = X509_NAME_get_index_by_OBJ(subject, entries.at(i).first.getObjectIdentifier(), -1);
		X509_NAME_ENTRY* ne;
		std::string data = entries.at(i).second;
		if (!data.empty())
		{
			if (nameEntryPos >= 0)
			{
				ne = X509_NAME_get_entry(subject, nameEntryPos);
				int rc = X509_NAME_ENTRY_set_data(ne, ne->value->type, (unsigned char *)data.c_str(), data.length());
				if (!rc)
				{
					throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::setSubject");
				}
			}
			else
			{
				ne = X509_NAME_ENTRY_new();
				X509_NAME_ENTRY_set_object(ne, entries.at(i).first.getObjectIdentifier());
				X509_NAME_ENTRY_set_data(ne, entryType, (unsigned char *)data.c_str(), data.length());
				X509_NAME_add_entry(subject, ne, -1, 0);
				X509_NAME_ENTRY_free(ne);
			}
		}
	}
	name = RDNSequence(subject);*/
}

void CertificateBuilder::setSubject(const RDNSequence &name)
{
	X509_NAME *subject = NULL;
	int rc = 0;

	subject = name.getX509Name();
	rc = X509_set_subject_name(this->cert, subject);
	X509_NAME_free(subject);
	if (rc == 0) {
		throw CertificationException(CertificationException::INVALID_RDN_SEQUENCE,
				"CertificateBuilder::setSubject");
	}
}

void CertificateBuilder::setSubject(X509_REQ* req)
{
	X509_NAME *name = NULL;
	int rc = 0;

	name = X509_REQ_get_subject_name(req);
	if(name == NULL) {
		throw CertificationException(CertificationException::INVALID_RDN_SEQUENCE, "CertificateBuilder::setSubject");
	}

	rc = X509_set_subject_name(this->cert, name);
	if (!rc) {
		throw CertificationException(CertificationException::INVALID_RDN_SEQUENCE, "CertificateBuilder::setSubject");
	}
}

RDNSequence CertificateBuilder::getSubject()
{
	X509_NAME *name = NULL;
	name = X509_get_subject_name(this->cert);
	return RDNSequence(name);
}

void CertificateBuilder::addExtension(const Extension& extension)
{
	X509_EXTENSION *ext = NULL;
	int rc = 0;

	ext = extension.getX509Extension();
	rc = X509_add_ext(this->cert, ext, -1);
	if (!rc) {
		throw CertificationException(CertificationException::ADDING_EXTENSION, "CertificateBuilder::addExtension");
	}
}

void CertificateBuilder::addExtensions(const std::vector<Extension *>& extensions)
{
	X509_EXTENSION *x509Ext = NULL;
	int rc = 0;

	for (auto ext : extensions)
	{
		x509Ext = ext->getX509Extension();
		rc = X509_add_ext(this->cert, x509Ext, -1);
		if (!rc) {
			throw CertificationException(CertificationException::ADDING_EXTENSION, "CertificateBuilder::addExtension");
		}
		X509_EXTENSION_free(x509Ext);
	}
}

void CertificateBuilder::replaceExtension(const Extension &extension)
{
	int position = 0, rc = 0;
	X509_EXTENSION *ext = NULL;
	ObjectIdentifier oid = extension.getObjectIdentifier();

	position = X509_get_ext_by_OBJ(this->cert, oid.getObjectIdentifier(), -1);
	if (position >= 0) {
		ext = extension.getX509Extension();
		rc = X509_add_ext(this->cert, ext, position);
		if(rc == 0) {
			throw CertificationException(CertificationException::ADDING_EXTENSION, "CertificateBuilder::replaceExtension");
		}
		ext = X509_delete_ext(this->cert, position + 1);
		X509_EXTENSION_free(ext);
	} else {  // a extensao nao esta presente, adiciona no topo da pilha
		this->addExtension(extension);
	}
}

std::vector<Extension*> CertificateBuilder::getExtension(Extension::Name extensionName)
{
	Extension *oneExt = NULL;
	X509_EXTENSION *ext = NULL;
	std::vector<Extension*> ret;
	int next = 0, i = 0;

	next = X509_get_ext_count(this->cert);
	for (i = 0; i < next; i++) {
		ext = X509_get_ext(this->cert, i);
		if (Extension::getName(ext) == extensionName) {
			oneExt = ExtensionFactory::getExtension(ext);
			ret.push_back(oneExt);
		}
	}
	return ret;
}

std::vector<Extension*> CertificateBuilder::getExtensions()
{
	Extension *oneExt = NULL;
	X509_EXTENSION *ext = NULL;
	std::vector<Extension*> ret;
	int next = 0, i = 0;

	next = X509_get_ext_count(this->cert);
	for (i = 0; i < next; i++) {
		ext = X509_get_ext(this->cert, i);
		oneExt = ExtensionFactory::getExtension(ext);
		ret.push_back(oneExt);
	}
	return ret;
}

std::vector<Extension*> CertificateBuilder::getUnknownExtensions()
{
	Extension *oneExt = NULL;
	X509_EXTENSION *ext = NULL;
	std::vector<Extension*> ret;
	int next = 0, i = 0;

	next = X509_get_ext_count(this->cert);
	for (i = 0; i < next; i++) {
		ext = X509_get_ext(this->cert, i);
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

std::vector<Extension*> CertificateBuilder::removeExtension(Extension::Name extensionName)
{
	Extension *oneExt = NULL;
	X509_EXTENSION *ext = NULL;
	std::vector<Extension*> ret;
	int i = 0;

	while(i < X509_get_ext_count(this->cert)) {
		ext = X509_get_ext(this->cert, i);
		if (Extension::getName(ext) == extensionName) {
			oneExt = ExtensionFactory::getExtension(ext);
			ret.push_back(oneExt);
			ext = X509_delete_ext(this->cert, i);
			X509_EXTENSION_free(ext);
			// nao incrementa i pois um elemento do array foi removido
		} else {
			i++;
		}
	}

	return ret;

}

std::vector<Extension*> CertificateBuilder::removeExtension(const ObjectIdentifier& extOID)
{
	Extension *oneExt = NULL;
	ASN1_OBJECT* obj = NULL;
	X509_EXTENSION *ext = NULL;
	std::vector<Extension *> ret;
	int i = 0;

	while(i < X509_get_ext_count(this->cert)) {
		ext = X509_get_ext(this->cert, i);
		obj = X509_EXTENSION_get_object(ext);

		if (OBJ_cmp(obj, extOID.getObjectIdentifier()) == 0) {
			oneExt = ExtensionFactory::getExtension(ext);
			ret.push_back(oneExt);
			ext = X509_delete_ext(this->cert, i);
			X509_EXTENSION_free(ext);
			// nao incrementa i pois um elemento do array foi removido
		} else {
			i++;
		}
	}
	return ret;
}

Certificate CertificateBuilder::sign(PrivateKey& privateKey, MessageDigest::Algorithm messageDigestAlgorithm)
{
	PublicKey pub = this->getPublicKey();
	DateTime dateTime;
	int rc;

	rc = X509_sign(this->cert, privateKey.getEvpPkey(),
			MessageDigest::getMessageDigest(messageDigestAlgorithm));
	if (!rc) {
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::sign");
	}

	return Certificate((const X509*) this->cert);
}

const X509* CertificateBuilder::getX509() const
{
	return this->cert;
}

bool CertificateBuilder::isIncludeEcdsaParameters() const {
	return this->includeECDSAParameters;
}

void CertificateBuilder::setIncludeEcdsaParameters(bool includeEcdsaParameters) {
	this->includeECDSAParameters = includeEcdsaParameters;
}

void CertificateBuilder::includeEcdsaParameters() {
	PublicKey publicKey = this->getPublicKey();

	if(publicKey.getAlgorithm() == AsymmetricKey::EC && this->isIncludeEcdsaParameters()) {
		EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(publicKey.getEvpPkey());
		EC_KEY_set_asn1_flag(ec_key, 0);
	}
	this->setPublicKey(publicKey);
}

int CertificateBuilder::getCodification(const RDNSequence& name){
	int entryType = MBSTRING_ASC;
	X509_NAME *subject = X509_get_subject_name(this->cert);
	if(subject == NULL) {
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::alterSubject");
	}

	std::vector<std::pair<ObjectIdentifier, std::string> > entries = name.getEntries();

	for(auto entry : entries) {
		int position = X509_NAME_get_index_by_NID(subject, entry.first.getNid(), -1);
		if(position != -1 && entry.first.getNid() != NID_countryName) {
			X509_NAME_ENTRY* oldEntry = X509_NAME_get_entry(subject, position);
			ASN1_OBJECT* obj = X509_NAME_ENTRY_get_object(oldEntry);
			entryType = OBJ_obj2nid(obj);
			if(entryType != MBSTRING_FLAG) {
				return entryType;
			}
		}
	}

	return entryType;
}
