#include <libcryptosec/certificate/CertificateBuilder.h>

#include <libcryptosec/certificate/CertificateRequest.h>
#include <libcryptosec/certificate/extension/Extension.h>
#include <libcryptosec/certificate/extension/ExtensionFactory.h>
#include <libcryptosec/asymmetric/PrivateKey.h>
#include <libcryptosec/asymmetric/PublicKey.h>
#include <libcryptosec/DateTime.h>
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/ByteArray.h>
#include <libcryptosec/Base64.h>
#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/AsymmetricKeyException.h>
#include <libcryptosec/exception/DecodeException.h>
#include <libcryptosec/exception/EncodeException.h>

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
	ASN1_INTEGER* asn1Integer = serial.toAsn1Integer();
	int rc = X509_set_serialNumber(this->cert, asn1Integer);
	ASN1_INTEGER_free(asn1Integer);
	THROW_ENCODE_ERROR_IF(rc == 0);
}

void CertificateBuilder::setPublicKey(const PublicKey& publicKey)
{
	const EVP_PKEY *pkey = publicKey.getEvpPkey();
	int rc = X509_set_pubkey(this->cert, (EVP_PKEY*) pkey);
	THROW_ENCODE_ERROR_IF(rc == 0);
}

void CertificateBuilder::setVersion(long version)
{
	int rc = X509_set_version(this->cert, version);
	THROW_ENCODE_ERROR_IF(rc == 0);
}

void CertificateBuilder::setNotBefore(const DateTime &dateTime)
{
	ASN1_TIME *asn1Time = dateTime.toAsn1Time();
	int rc = X509_set1_notBefore(this->cert, asn1Time);
	ASN1_TIME_free(asn1Time);
	THROW_ENCODE_ERROR_IF(rc == 0);
}

void CertificateBuilder::setNotAfter(const DateTime &dateTime)
{
	ASN1_TIME *asn1Time = dateTime.toAsn1Time();
	int rc = X509_set1_notAfter(this->cert, asn1Time);
	ASN1_TIME_free(asn1Time);
	THROW_ENCODE_ERROR_IF(rc == 0);
}

void CertificateBuilder::setIssuer(const RDNSequence &name)
{
	X509_NAME *issuer = name.getSslObject();
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
	X509_NAME *subject = name.getSslObject();
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
		THROW_ENCODE_ERROR_AND_FREE_IF(ext == NULL,
				for (auto extension : ret) {
					delete extension;
				}
		);

		if (Extension::getName(ext) == extensionName) {
			Extension *oneExt = ExtensionFactory::getExtension(ext);
			ret.push_back(oneExt);
			ext = X509_delete_ext(this->cert, i);
			THROW_ENCODE_ERROR_AND_FREE_IF(ext == NULL,
					for (auto extension : ret) {
						delete extension;
					}
			);
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
	ASN1_OBJECT *oid = extOID.getSslObject();
	std::vector<Extension*> ret;
	int i = 0;

	while(i < X509_get_ext_count(this->cert)) {
		X509_EXTENSION *ext = X509_get_ext(this->cert, i);
		THROW_ENCODE_ERROR_AND_FREE_IF(ext == NULL,
				ASN1_OBJECT_free(oid);
				for (auto extension : ret) {
					delete extension;
				}
		);

		const ASN1_OBJECT *currentOid = X509_EXTENSION_get_object(ext);
		THROW_ENCODE_ERROR_AND_FREE_IF(currentOid == NULL,
				ASN1_OBJECT_free(oid);
				for (auto extension : ret) {
					delete extension;
				}
		);

		if (OBJ_cmp(currentOid, oid) == 0) {
			Extension *oneExt = ExtensionFactory::getExtension(ext);
			ret.push_back(oneExt);
			ext = X509_delete_ext(this->cert, i);
			THROW_ENCODE_ERROR_AND_FREE_IF(ext == NULL,
					ASN1_OBJECT_free(oid);
					for (auto extension : ret) {
						delete extension;
					}
			);

			X509_EXTENSION_free(ext);
			// nao incrementa i pois um elemento do array foi removido
		} else {
			i++;
		}
	}

	ASN1_OBJECT_free(oid);
	return ret;
}

Certificate CertificateBuilder::sign(const PrivateKey& privateKey, MessageDigest::Algorithm messageDigestAlgorithm)
{
	const EVP_MD *md = MessageDigest::getMessageDigest(messageDigestAlgorithm);

	int rc = X509_sign(this->cert, (EVP_PKEY*) privateKey.getEvpPkey(), md);
	THROW_ENCODE_ERROR_IF(rc == 0);

	// TODO: should we reset the builder after sign?
	Certificate ret ((const X509*) this->cert);
	return ret;
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

// TODO: a lógica para essas funções de includeEcdsaParameters está estranha
void CertificateBuilder::includeEcdsaParameters() {
	PublicKey publicKey = this->getPublicKey();

	if(publicKey.getAlgorithm() == AsymmetricKey::EC && this->isIncludeEcdsaParameters()) {
		const EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY((EVP_PKEY*) publicKey.getEvpPkey());
		THROW_ENCODE_ERROR_IF(ec_key == NULL);

		// CAST: TODO
		EC_KEY_set_asn1_flag((EC_KEY*) ec_key, 0);
	}

	this->setPublicKey(publicKey);
}

int CertificateBuilder::getCodification(const RDNSequence& name){
	int entryType = MBSTRING_ASC;

	const X509_NAME *subject = X509_get_subject_name(this->cert);
	THROW_DECODE_ERROR_IF(subject == NULL);

	const std::vector<std::pair<ObjectIdentifier, std::string>> &entries = name.getEntries();
	for(auto entry : entries) {
		int position = X509_NAME_get_index_by_NID((X509_NAME*) subject, entry.first.getNid(), -1);
		if(position != -1 && entry.first.getNid() != NID_countryName) {
			const X509_NAME_ENTRY* oldEntry = X509_NAME_get_entry(subject, position);
			THROW_DECODE_ERROR_IF(oldEntry == NULL);

			const ASN1_STRING* data = X509_NAME_ENTRY_get_data(oldEntry);
			THROW_DECODE_ERROR_IF(data == NULL);

			entryType = data->type;
			if(entryType != MBSTRING_FLAG) {
				return entryType;
			}
		}
	}

	return entryType;
}
