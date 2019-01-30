#include <libcryptosec/certificate/CertificateRequest.h>

#include <libcryptosec/Base64.h>
#include <libcryptosec/certificate/extension/ExtensionFactory.h>
#include <libcryptosec/exception/EncodeException.h>

#include <openssl/pem.h>

#include <sstream>

CertificateRequest::CertificateRequest() :
		req(X509_REQ_new())
{
	THROW_DECODE_ERROR_IF(this->req == NULL);
}

CertificateRequest::CertificateRequest(X509_REQ *req) :
		req(req)
{
	THROW_DECODE_ERROR_IF(this->req == NULL);
}

CertificateRequest::CertificateRequest(const X509_REQ* req) :
		req(X509_REQ_dup((X509_REQ*) req))
{
	THROW_DECODE_ERROR_IF(this->req == NULL);
}

CertificateRequest::CertificateRequest(const std::string& pemEncoded)
{
	DECODE_PEM(this->req, pemEncoded, PEM_read_bio_X509_REQ);
}

CertificateRequest::CertificateRequest(const ByteArray& derEncoded)
{
	DECODE_DER(this->req, derEncoded, d2i_X509_REQ_bio);
}

CertificateRequest::CertificateRequest(const CertificateRequest& req) :
		req(X509_REQ_dup(req.req))
{
	THROW_DECODE_ERROR_IF(this->req == NULL);
}

CertificateRequest::CertificateRequest(CertificateRequest&& req) :
		req(std::move(req.req))
{
	req.req = NULL;
}

CertificateRequest::~CertificateRequest()
{
	X509_REQ_free(this->req);
}

CertificateRequest& CertificateRequest::operator=(const CertificateRequest& req)
{
	if (&req == this) {
		return *this;
	}

	X509_REQ *clone = X509_REQ_dup(req.req);
	THROW_DECODE_ERROR_IF(clone == NULL);

	if (this->req != NULL) {
		X509_REQ_free(this->req);
	}

	this->req = clone;

	return *this;
}

CertificateRequest& CertificateRequest::operator=(CertificateRequest&& req)
{
	if (&req == this) {
		return *this;
	}

	if (this->req != NULL) {
		X509_REQ_free(this->req);
	}

	this->req = std::move(req.req);
	req.req = NULL;

	return *this;
}

void CertificateRequest::setVersion(long version)
{
	int rc = X509_REQ_set_version(this->req, version);
	THROW_ENCODE_ERROR_IF(rc == 0);
}

long CertificateRequest::getVersion() const
{
	return X509_REQ_get_version(this->req);
}

MessageDigest::Algorithm CertificateRequest::getMessageDigestAlgorithm() const
{
	int nid = X509_REQ_get_signature_nid(this->req);
	MessageDigest::Algorithm ret = MessageDigest::getMessageDigest(nid);
	return ret;
}

void CertificateRequest::setPublicKey(const PublicKey& publicKey)
{
	const EVP_PKEY *pkey = publicKey.getEvpPkey();
	int rc = X509_REQ_set_pubkey(this->req, (EVP_PKEY*) pkey);
	THROW_ENCODE_ERROR_IF(rc == 0);
}

PublicKey CertificateRequest::getPublicKey() const
{
	const EVP_PKEY *key = X509_REQ_get0_pubkey(this->req);
	THROW_DECODE_ERROR_IF(key == NULL);
	PublicKey ret(key);
	return ret;
}

ByteArray CertificateRequest::getPublicKeyInfo() const
{
	throw std::exception();
	// TODO: openssl não provê uma função para pegar os bits da chave pública
/*	ByteArray ret;
	unsigned int size;
	ASN1_BIT_STRING *pubKeyBits;
	if (X509_REQ_get0_pubkey(this->req) == NULL)
	{
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateBuilder::getPublicKeyInfo");
	}
	X509_REQ_get0_pubkey(this->req);
	X509_PUBKEY* pubKey = X509_REQ_get_X509_PUBKEY(this->req);
	temp = this->req->req_info->pubkey->public_key;
	ret = ByteArray(EVP_MAX_MD_SIZE);

	// TODO: sempre sha1?
	EVP_Digest(temp->data, temp->length, ret.getDataPointer(), &size, EVP_sha1(), NULL);
	ret = ByteArray(ret.getDataPointer(), size);

	return ret;
*/
}

void CertificateRequest::setSubject(const RDNSequence& name)
{
	X509_NAME *subject = name.getX509Name();
	int rc = X509_REQ_set_subject_name(this->req, subject);
	X509_NAME_free(subject);
	THROW_ENCODE_ERROR_IF(rc == 0);
}

RDNSequence CertificateRequest::getSubject() const
{
	const X509_NAME *name = X509_REQ_get_subject_name(this->req);
	THROW_DECODE_ERROR_IF(name == NULL);
	RDNSequence ret(name);
	return ret;
}

void CertificateRequest::addExtension(const Extension& extension)
{
	X509_ATTRIBUTE *attr = NULL;
	// TODO: verificar - retorna uma cópia da lista de extensões da requisição
	STACK_OF(X509_EXTENSION) *extensions = X509_REQ_get_extensions(this->req);

	if (!extensions) {
		extensions = sk_X509_EXTENSION_new_null();
		THROW_ENCODE_ERROR_IF(extensions == NULL);
	} else {
		int pos = X509_REQ_get_attr_by_NID(this->req, NID_ext_req, -1);
		THROW_ENCODE_ERROR_AND_FREE_IF(pos < 0,
				sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
		);

		attr = X509_REQ_delete_attr(this->req, pos);
		THROW_ENCODE_ERROR_AND_FREE_IF(attr == NULL,
				sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
		);

		// não deletamos o atributo ainda para tentar reinseri-lo no caso
		// de um erro futuro.
	}

	// Tenta inserir a extensão na stack
	X509_EXTENSION *ext = extension.getX509Extension();
	int rc = sk_X509_EXTENSION_push(extensions, ext);
	THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
			X509_EXTENSION_free(ext);
			sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
	);

	// Tenta inserir a stack na requisição
	rc = X509_REQ_add_extensions(this->req, extensions);
	THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
			X509_REQ_add1_attr(this->req, attr);  // Tenta reinserir o atributo antigo
			X509_ATTRIBUTE_free(attr);
			sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
	);

	X509_ATTRIBUTE_free(attr);

	// TODO: verificar se X509_REQ_add_extensions move ou copia
	// se mover, não podemos desalocar aqui
	sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
}

void CertificateRequest::addExtensions(const std::vector<Extension*>& extensions)
{
	if (extensions.size() > 0) {
		int rc = 0;

		STACK_OF(X509_EXTENSION) *extensionsStack = sk_X509_EXTENSION_new_null();
		THROW_ENCODE_ERROR_IF(extensionsStack == NULL);

		for (auto extension : extensions) {
			X509_EXTENSION *ext = extension->getX509Extension();
			rc = sk_X509_EXTENSION_push(extensionsStack, ext);
			THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
					sk_X509_EXTENSION_pop_free(extensionsStack, X509_EXTENSION_free);
					X509_EXTENSION_free(ext);
			);
		}

		rc = X509_REQ_add_extensions(this->req, extensionsStack);
		THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
				sk_X509_EXTENSION_pop_free(extensionsStack, X509_EXTENSION_free);
		);

		// TODO: verificar se X509_REQ_add_extensions copia ou move a stack
		// Se mover, não modemos desalocar aqui
		sk_X509_EXTENSION_pop_free(extensionsStack, X509_EXTENSION_free);
	}
}

void CertificateRequest::replaceExtension(const Extension& extension)
{
	X509_EXTENSION *ext = extension.getX509Extension();
	int rc = 0;

	// TODO: verificar - pega uma copia da pilha de extencoes da req
	STACK_OF(X509_EXTENSION) *extensionsStack = X509_REQ_get_extensions(this->req);

	if(extensionsStack == NULL) { //pilha nao instanciada
		extensionsStack = sk_X509_EXTENSION_new_null();
		THROW_ENCODE_ERROR_AND_FREE_IF(extensionsStack == NULL,
				X509_EXTENSION_free(ext);
		);

		rc = sk_X509_EXTENSION_push(extensionsStack, ext);
		THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
				X509_EXTENSION_free(ext);
				sk_X509_EXTENSION_pop_free(extensionsStack, X509_EXTENSION_free);
		);

		rc = X509_REQ_add_extensions(this->req, extensionsStack);  // adiciona nova pilha a req
		THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
				sk_X509_EXTENSION_pop_free(extensionsStack, X509_EXTENSION_free);
		);
	} else { //pilha instanciada previamente
		ASN1_OBJECT *oid = extension.getObjectIdentifier().getSslObject();
		int position =  X509v3_get_ext_by_OBJ(extensionsStack, oid, -1);
		ASN1_OBJECT_free(oid);

		if (position >= 0) {
			X509_EXTENSION *oldExt = sk_X509_EXTENSION_delete(extensionsStack, position);
			THROW_ENCODE_ERROR_AND_FREE_IF(oldExt == NULL,
					X509_EXTENSION_free(ext);
					sk_X509_EXTENSION_pop_free(extensionsStack, X509_EXTENSION_free);
			);

			X509_EXTENSION_free(oldExt);

			rc = sk_X509_EXTENSION_insert(extensionsStack, ext, position);
			THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
					X509_EXTENSION_free(ext);
					sk_X509_EXTENSION_pop_free(extensionsStack, X509_EXTENSION_free);
			);
		} else { //pilha vazia ou sem a extensao previamente adicionada
			rc = sk_X509_EXTENSION_insert(extensionsStack, ext, -1);
			THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
					X509_EXTENSION_free(ext);
					sk_X509_EXTENSION_pop_free(extensionsStack, X509_EXTENSION_free);
			);
		}

		position = X509_REQ_get_attr_by_NID(this->req, NID_ext_req, -1);
		THROW_ENCODE_ERROR_AND_FREE_IF(position < 0,
				sk_X509_EXTENSION_pop_free(extensionsStack, X509_EXTENSION_free);
		);

		X509_ATTRIBUTE *attr = X509_REQ_delete_attr(this->req, position);  // remove pilha antiga da req
		THROW_ENCODE_ERROR_AND_FREE_IF(attr == NULL,
				sk_X509_EXTENSION_pop_free(extensionsStack, X509_EXTENSION_free);
		);

		rc = X509_REQ_add_extensions(this->req, extensionsStack);  // adiciona nova pilha a req
		THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
				X509_REQ_add1_attr(this->req, attr); // Tenta reinserir o atributo antigo
				X509_ATTRIBUTE_free(attr);
				sk_X509_EXTENSION_pop_free(extensionsStack, X509_EXTENSION_free);
		);
		X509_ATTRIBUTE_free(attr);
	}

	// TODO: verificar se X509_REQ_add_extensions copia ou move
	// Se mover, não podemos desalocar a stack
	sk_X509_EXTENSION_pop_free(extensionsStack, X509_EXTENSION_free); //apaga copia local da pilha
}

std::vector<Extension*> CertificateRequest::removeExtension(Extension::Name extensionName)
{
	std::vector<Extension*> ret;
	bool stackChange = false;

	// TODO: verificar
	// pega uma copia da pilha de extencoes da req
	STACK_OF(X509_EXTENSION) *extensionsStack = X509_REQ_get_extensions(this->req);
	THROW_ENCODE_ERROR_IF(extensionsStack == NULL);

	int i = 0;
	while(i < sk_X509_EXTENSION_num(extensionsStack)) {
		X509_EXTENSION *ext = sk_X509_EXTENSION_value(extensionsStack, i);
		THROW_ENCODE_ERROR_AND_FREE_IF(ext == NULL,
				sk_X509_EXTENSION_pop_free(extensionsStack, X509_EXTENSION_free);
				for (auto extension : ret) {
					delete extension;
				}
		);

		if (Extension::getName(ext) == extensionName) {
			Extension *oneExt = ExtensionFactory::getExtension(ext);
			ret.push_back(oneExt);

			ext = sk_X509_EXTENSION_delete(extensionsStack, i);
			THROW_ENCODE_ERROR_AND_FREE_IF(ext == NULL,
					sk_X509_EXTENSION_pop_free(extensionsStack, X509_EXTENSION_free);
					for (auto extension : ret) {
						delete extension;
					}
			);

			X509_EXTENSION_free(ext);

			//nao incrementa i pois um elemento do array foi removido
			stackChange = true;
		} else {
			i++;
		}
	}

	if(stackChange) {
		int position = X509_REQ_get_attr_by_NID(this->req, NID_ext_req, -1);  // remove pilha antiga da req
		if (position >= 0) {
			X509_ATTRIBUTE *attr = X509_REQ_delete_attr(this->req, position);
			THROW_ENCODE_ERROR_AND_FREE_IF(attr == NULL,
					sk_X509_EXTENSION_pop_free(extensionsStack, X509_EXTENSION_free);
					for (auto extension : ret) {
						delete extension;
					}
			);

			// adiciona nova pilha a req
			int rc = X509_REQ_add_extensions(this->req, extensionsStack);
			THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
					X509_REQ_add1_attr(this->req, attr);  // tenta reinserir a stack anterior
					X509_ATTRIBUTE_free(attr);
					sk_X509_EXTENSION_pop_free(extensionsStack, X509_EXTENSION_free);
					for (auto extension : ret) {
						delete extension;
					}
			);
			X509_ATTRIBUTE_free(attr);
			sk_X509_EXTENSION_pop_free(extensionsStack, X509_EXTENSION_free);  // remove copia local da pilha
		}
	}

	return ret;
}


std::vector<Extension*> CertificateRequest::removeExtension(const ObjectIdentifier& extOID)
{
	int nid = extOID.getNid();
	Extension::Name name = Extension::getName(nid);
	std::vector<Extension*> extensions = this->removeExtension(name);
	return extensions;
}

std::vector<Extension*> CertificateRequest::getExtension(Extension::Name extensionName) const
{
	std::vector<Extension*> ret;

	// TODO: verificar - retorna uma cópia da lista de extensões da requisição
	STACK_OF(X509_EXTENSION) *extensions = X509_REQ_get_extensions(this->req);
	if (extensions == NULL) {
		return ret;
	}

	int num = sk_X509_EXTENSION_num(extensions);
	for (int i = 0; i < num; i++) {
		const X509_EXTENSION *ext = sk_X509_EXTENSION_value(extensions, i);
		THROW_DECODE_ERROR_AND_FREE_IF(ext == NULL,
				sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);

				for (auto extension : ret) {
					delete extension;
				}
		);

		if (Extension::getName(ext) == extensionName) {
			Extension *oneExt = ExtensionFactory::getExtension(ext);
			ret.push_back(oneExt);
		}
	}

	sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
	return ret;
}

std::vector<Extension*> CertificateRequest::getExtensions() const
{
	std::vector<Extension*> ret;
	STACK_OF(X509_EXTENSION) *extensions = X509_REQ_get_extensions(this->req);
	if (extensions == NULL) {
		return ret;
	}

	int num = sk_X509_EXTENSION_num(extensions);
	for (int i = 0; i < num; i++) {
		const X509_EXTENSION *ext = sk_X509_EXTENSION_value(extensions, i);
		THROW_DECODE_ERROR_AND_FREE_IF(ext == NULL,
				sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);

				for (auto extension : ret) {
					delete extension;
				}
		);

		Extension *oneExt = ExtensionFactory::getExtension(ext);
		ret.push_back(oneExt);
	}

	sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
	return ret;
}

std::vector<Extension*> CertificateRequest::getUnknownExtensions() const
{
	std::vector<Extension*> ret;
	Extension *oneExt = NULL;

	// TODO: verificar - retorna uma cópia da lista de extensões da requisição
	STACK_OF(X509_EXTENSION) *extensions = X509_REQ_get_extensions(this->req);
	if (extensions == NULL) {
		return ret;
	}

	int num = sk_X509_EXTENSION_num(extensions);
	for (int i = 0; i < num; i++) {
		const X509_EXTENSION *ext = sk_X509_EXTENSION_value(extensions, i);
		THROW_DECODE_ERROR_AND_FREE_IF(ext == NULL,
				sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);

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

	sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
	return ret;
}

ByteArray CertificateRequest::getFingerPrint(MessageDigest::Algorithm algorithm) const
{
	MessageDigest messageDigest(algorithm);
	ByteArray derEncoded = this->getDerEncoded();
	ByteArray ret = messageDigest.doFinal(std::move(derEncoded));
	return ret;
}

void CertificateRequest::sign(const PrivateKey& privateKey, MessageDigest::Algorithm messageDigestAlgorithm)
{
	// CAST: TODO
	int rc = X509_REQ_sign(this->req, (EVP_PKEY*) privateKey.getEvpPkey(), MessageDigest::getMessageDigest(messageDigestAlgorithm));
	THROW_IF(rc == 0, CertificationException, CertificationException::INTERNAL_ERROR); // TODO: check exception type
}

bool CertificateRequest::verify() const
{
	PublicKey pub = this->getPublicKey();
	// CAST: TODO
	int rc = X509_REQ_verify(this->req, (EVP_PKEY*) pub.getEvpPkey());
	return (rc == 1 ? true : false);
}

bool CertificateRequest::isSigned() const
{
	const ASN1_BIT_STRING* signature;
	X509_REQ_get0_signature(this->req, &signature, 0);
	THROW_DECODE_ERROR_IF(signature == NULL);
	return signature->data != NULL && signature->length > 0;
}

std::string CertificateRequest::toXml(const std::string& tab) const
{
	std::stringstream stream;
	std::string ret, string;
	RDNSequence subject;
	std::vector<Extension *> extensions;
	ByteArray publicKeyInfo;
	long value;

	ret = tab + "<certificateRequest>\n";

		value = this->getVersion();
		stream << value;
		string = stream.str();

		ret += tab + "\t<version>" + string + "</version>\n";

		ret += tab + "\t<subject>\n";
		subject = this->getSubject();
		ret += subject.getXmlEncoded(tab + "\t\t");
		ret += tab + "\t</subject>\n";

		try {
			publicKeyInfo = this->getPublicKeyInfo();
			ret += tab + "\t<publicKeyInfo>\n";
			ret += tab + "\t\t" + Base64::encode(publicKeyInfo) + "\n";
			ret += tab + "\t</publicKeyInfo>\n";
		} catch (...) {
		}

		ret += tab + "\t<extensions>\n";
		extensions = this->getExtensions();
		for (auto extension : extensions) {
			ret += extension->toXml(tab + "\t\t");
			delete extension;
		}
		ret += tab + "\t</extensions>\n";

	ret += tab + "</certificateRequest>\n";

	return ret;
}

std::string CertificateRequest::getPemEncoded() const
{
	ENCODE_PEM_AND_RETURN(this->req, PEM_write_bio_X509_REQ);
}

ByteArray CertificateRequest::getDerEncoded() const
{
	ENCODE_DER_AND_RETURN(this->req, i2d_X509_REQ_bio);
}

X509_REQ* CertificateRequest::getSslObject() const
{
	X509_REQ *clone = X509_REQ_dup(this->req);
	THROW_ENCODE_ERROR_IF(clone == NULL);
	return clone;
}

const X509_REQ* CertificateRequest::getX509Req() const
{
	return this->req;
}
