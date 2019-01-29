#include <libcryptosec/certificate/CertificateBuilder.h>

#include <libcryptosec/certificate/CertificateRequest.h>
#include <libcryptosec/certificate/extension/Extension.h>
#include <libcryptosec/certificate/extension/ExtensionFactory.h>
#include <libcryptosec/exception/AsymmetricKeyException.h>
#include <libcryptosec/exception/CertificationException.h>
#include <libcryptosec/exception/EncodeException.h>
#include <libcryptosec/PrivateKey.h>
#include <libcryptosec/PublicKey.h>
#include <libcryptosec/DateTime.h>
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/ByteArray.h>
#include <libcryptosec/Base64.h>

#include <openssl/pem.h>

CertificateBuilder::CertificateBuilder() :
		Certificate(X509_new()),
		includeECDSAParameters(false)
{
	THROW_ENCODE_ERROR_IF(this->cert == NULL);
	DateTime dateTime;
	this->setNotBefore(dateTime);
	this->setNotAfter(dateTime);
}

CertificateBuilder::CertificateBuilder(const std::string& pemEncoded) :
		Certificate(pemEncoded),
		includeECDSAParameters(false)
{
}

CertificateBuilder::CertificateBuilder(const ByteArray& derEncoded) :
		Certificate(derEncoded),
		includeECDSAParameters(false)
{
}

CertificateBuilder::CertificateBuilder(const CertificateRequest& request) :
		CertificateBuilder()
{
	this->setSubject(request.getX509Req());

	PublicKey publicKey = request.getPublicKey();
	this->setPublicKey(publicKey);

	std::vector<Extension*> extensions = request.getExtensions();
	for (auto extension : extensions) {
		this->addExtension(*extension);
		delete extension;
	}
}

CertificateBuilder::CertificateBuilder(const CertificateBuilder& cert) :
		Certificate(cert),
		includeECDSAParameters(false)
{
}

CertificateBuilder::CertificateBuilder(CertificateBuilder&& builder) :
		Certificate(std::move(builder)),
		includeECDSAParameters(std::move(builder.includeECDSAParameters))
{
}

CertificateBuilder::~CertificateBuilder()
{
}

CertificateBuilder& CertificateBuilder::operator=(const CertificateBuilder& builder)
{
	Certificate::operator=(builder);
    this->includeECDSAParameters = builder.includeECDSAParameters;
    return *this;
}

CertificateBuilder& CertificateBuilder::operator=(CertificateBuilder&& builder)
{
	Certificate::operator=(std::move(builder));
	this->includeECDSAParameters = builder.includeECDSAParameters;
	return *this;
}

void CertificateBuilder::setSerialNumber(long serial)
{
	ASN1_INTEGER* serialNumber = X509_get_serialNumber(this->cert);
	THROW_ENCODE_ERROR_IF(serialNumber == NULL);

	int rc = ASN1_INTEGER_set(serialNumber, serial);
	THROW_ENCODE_ERROR_IF(rc == 0);
}

void CertificateBuilder::setSerialNumber(const BigInteger& serial)
{
	ASN1_INTEGER* asn1Integer = serial.getASN1Value();
	int rc = X509_set_serialNumber(this->cert, asn1Integer);
	ASN1_INTEGER_free(asn1Integer);
	THROW_ENCODE_ERROR_IF(rc == 0);
}

void CertificateBuilder::setPublicKey(const PublicKey& publicKey)
{
	EVP_PKEY *pkey = publicKey.getEvpPkey();
	int rc = X509_set_pubkey(this->cert, pkey);
	EVP_PKEY_free(pkey);
	THROW_ENCODE_ERROR_IF(rc == 0);
}

void CertificateBuilder::setVersion(long version)
{
	int rc = X509_set_version(this->cert, version);
	THROW_ENCODE_ERROR_IF(rc == 0);
}

void CertificateBuilder::setNotBefore(const DateTime &dateTime)
{
	ASN1_TIME *asn1Time = dateTime.getAsn1Time();
	int rc = X509_set1_notBefore(this->cert, asn1Time);
	ASN1_TIME_free(asn1Time);
	THROW_ENCODE_ERROR_IF(rc == 0);
}

void CertificateBuilder::setNotAfter(const DateTime &dateTime)
{
	ASN1_TIME *asn1Time = dateTime.getAsn1Time();
	int rc = X509_set1_notAfter(this->cert, asn1Time);
	ASN1_TIME_free(asn1Time);
	THROW_ENCODE_ERROR_IF(rc == 0);
}

void CertificateBuilder::setIssuer(const RDNSequence &name)
{
	X509_NAME *issuer = name.getX509Name();
	int rc = X509_set_issuer_name(this->cert, issuer);
	X509_NAME_free(issuer);
	THROW_ENCODE_ERROR_IF(rc == 0);
}

void CertificateBuilder::setIssuer(const X509* issuer)
{
	const X509_NAME *name = X509_get_subject_name(issuer);
	THROW_ENCODE_ERROR_IF(name == NULL);

	// CAST: TODO
	int rc = X509_set_issuer_name(this->cert, (X509_NAME*) name);
	THROW_ENCODE_ERROR_IF(rc == 0);
}

void CertificateBuilder::alterSubject(const RDNSequence& name)
{
	int rc = 0;

	const X509_NAME *oldSubject = X509_get_subject_name(this->cert);
	THROW_ENCODE_ERROR_IF(oldSubject == NULL);

	X509_NAME *newSubject = X509_NAME_new();
	THROW_ENCODE_ERROR_IF(newSubject == NULL);

	const std::vector<std::pair<ObjectIdentifier, std::string>>& entries = name.getEntries();

	// TODO: essa lógica é confusa e precisa ser melhorada
	// Retorna a codificação da primeiro entrada que encontrar
	// no campo subject do certificado sendo montado. Se nenhuma
	// entrada for encontrada, retorna a codificação MBSTRING_ASC.
	// Essa função ignora o campo country.
	// A codificação retornada será usada apenas em entradas
	// adicionadas e não modificadas. Entradas modificadas usam a
	// mesma codificação da entrada antiga.
	int codification = this->getCodification(name);

	for(auto entry : entries) {
		X509_NAME_ENTRY *newEntry = X509_NAME_ENTRY_new();
		THROW_ENCODE_ERROR_AND_FREE_IF(newEntry == NULL,
				X509_NAME_free(newSubject);
		);

		// CAST: TODO
		int position = X509_NAME_get_index_by_NID((X509_NAME*) oldSubject, entry.first.getNid(), -1);

		if(!entry.second.empty()) {
			if(position != -1) {
				const X509_NAME_ENTRY* oldEntry = X509_NAME_get_entry(oldSubject, position);
				THROW_ENCODE_ERROR_AND_FREE_IF(oldEntry == NULL,
						X509_NAME_free(newSubject);
						X509_NAME_ENTRY_free(newEntry);
				);

				const ASN1_OBJECT* oldEntryOID = X509_NAME_ENTRY_get_object(oldEntry);
				THROW_ENCODE_ERROR_AND_FREE_IF(oldEntryOID == NULL,
						X509_NAME_free(newSubject);
						X509_NAME_ENTRY_free(newEntry);
				);

				int oldEntryNid = OBJ_obj2nid(oldEntryOID);
				THROW_ENCODE_ERROR_AND_FREE_IF(oldEntryNid == NID_undef,
						X509_NAME_free(newSubject);
						X509_NAME_ENTRY_free(newEntry);
				);

				const ASN1_STRING *oldEntryData = X509_NAME_ENTRY_get_data(oldEntry);
				THROW_ENCODE_ERROR_AND_FREE_IF(oldEntryData == NULL,
						X509_NAME_free(newSubject);
						X509_NAME_ENTRY_free(newEntry);
				);

				rc = X509_NAME_ENTRY_set_object(newEntry, oldEntryOID);
				THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
						X509_NAME_free(newSubject);
						X509_NAME_ENTRY_free(newEntry);
				);

				rc = X509_NAME_ENTRY_set_data(newEntry, oldEntryData->type, (const unsigned char*) entry.second.c_str(), entry.second.length());
				THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
						X509_NAME_free(newSubject);
						X509_NAME_ENTRY_free(newEntry);
				);

				rc = X509_NAME_add_entry(newSubject, newEntry, -1, 0);
				THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
						X509_NAME_free(newSubject);
						X509_NAME_ENTRY_free(newEntry);
				);

				X509_NAME_ENTRY_free(newEntry);

			} else {
				ASN1_OBJECT *oid = entry.first.getSslObject();
				rc = X509_NAME_ENTRY_set_object(newEntry, oid);
				ASN1_OBJECT_free(oid);
				THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
						X509_NAME_free(newSubject);
						X509_NAME_ENTRY_free(newEntry);
				);

				rc = X509_NAME_ENTRY_set_data(newEntry, codification, (const unsigned char *) entry.second.c_str(), entry.second.length());
				THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
						X509_NAME_free(newSubject);
						X509_NAME_ENTRY_free(newEntry);
				);

				rc = X509_NAME_add_entry(newSubject, newEntry, -1, 0);
				THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
						X509_NAME_free(newSubject);
						X509_NAME_ENTRY_free(newEntry);
				);

				X509_NAME_ENTRY_free(newEntry);
			}
		}
	}

	rc = X509_set_subject_name(this->cert, newSubject);
	X509_NAME_free(newSubject);
	THROW_ENCODE_ERROR_IF(rc == 0);
}

void CertificateBuilder::setSubject(const RDNSequence &name)
{
	X509_NAME *subject = name.getX509Name();
	int rc = X509_set_subject_name(this->cert, subject);
	X509_NAME_free(subject);
	THROW_ENCODE_ERROR_IF(rc == 0);
}

void CertificateBuilder::setSubject(const X509_REQ* req)
{
	const X509_NAME *name = X509_REQ_get_subject_name(req);
	THROW_ENCODE_ERROR_IF(name == NULL);

	// CAST: TODO
	int rc = X509_set_subject_name(this->cert, (X509_NAME*) name);
	THROW_ENCODE_ERROR_IF(rc == 0);
}

void CertificateBuilder::addExtension(const Extension& extension)
{
	X509_EXTENSION *ext = extension.getX509Extension();
	int rc = X509_add_ext(this->cert, ext, -1);
	X509_EXTENSION_free(ext);
	THROW_ENCODE_ERROR_IF(rc == 0);
}

void CertificateBuilder::addExtensions(const std::vector<Extension*>& extensions)
{
	for (auto ext : extensions) {
		X509_EXTENSION *x509Ext = ext->getX509Extension();
		int rc = X509_add_ext(this->cert, x509Ext, -1);
		X509_EXTENSION_free(x509Ext);
		THROW_ENCODE_ERROR_IF(rc == 0);
	}
}

void CertificateBuilder::replaceExtension(const Extension &extension)
{
	ObjectIdentifier oid = extension.getObjectIdentifier();

	int position = X509_get_ext_by_OBJ(this->cert, oid.getSslObject(), -1);
	if (position >= 0) {
		X509_EXTENSION *ext = extension.getX509Extension();

		int rc = X509_add_ext(this->cert, ext, position);
		X509_EXTENSION_free(ext);
		THROW_ENCODE_ERROR_IF(rc == 0);

		ext = X509_delete_ext(this->cert, position + 1);
		THROW_ENCODE_ERROR_IF(ext == 0);
		X509_EXTENSION_free(ext);
	} else {  // a extensao nao esta presente, adiciona no topo da pilha
		this->addExtension(extension);
	}
}

std::vector<Extension*> CertificateBuilder::removeExtension(Extension::Name extensionName)
{
	std::vector<Extension*> ret;
	int i = 0;

	while(i < X509_get_ext_count(this->cert)) {
		X509_EXTENSION *ext = X509_get_ext(this->cert, i);
		THROW_ENCODE_ERROR_IF(ext == NULL);

		if (Extension::getName(ext) == extensionName) {
			Extension *oneExt = ExtensionFactory::getExtension(ext);
			ret.push_back(oneExt);
			ext = X509_delete_ext(this->cert, i);
			THROW_ENCODE_ERROR_IF(ext == NULL);
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

		if (OBJ_cmp(obj, extOID.getSslObject()) == 0) {
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

Certificate CertificateBuilder::sign(const PrivateKey& privateKey, MessageDigest::Algorithm messageDigestAlgorithm)
{
	PublicKey pub = this->getPublicKey();
	DateTime dateTime;
	int rc;

	// TODO: cast ok?
	rc = X509_sign(this->cert, (EVP_PKEY*) privateKey.getEvpPkey(),
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
		// TODO: cast ok?
		EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY((EVP_PKEY*) publicKey.getEvpPkey());
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

	const std::vector<std::pair<ObjectIdentifier, std::string>> &entries = name.getEntries();
	for(auto entry : entries) {
		int position = X509_NAME_get_index_by_NID(subject, entry.first.getNid(), -1);
		if(position != -1 && entry.first.getNid() != NID_countryName) {
			X509_NAME_ENTRY* oldEntry = X509_NAME_get_entry(subject, position);
			ASN1_STRING* data = X509_NAME_ENTRY_get_data(oldEntry);
			entryType = data->type;
			if(entryType != MBSTRING_FLAG) {
				return entryType;
			}
		}
	}

	return entryType;
}


std::string CertificateBuilder::getXmlEncoded(const std::string& tab) const
{
	std::string ret, string;
	ByteArray data;
	char temp[15];
	long value;
	std::vector<Extension*> extensions;

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
			if (X509_get0_pubkey(this->cert)) {
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
		for (auto extension : extensions) {
			ret += extension->toXml("\t\t\t");
			delete extension;
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

std::string CertificateBuilder::toXml(const std::string& tab) const
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
