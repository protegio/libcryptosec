#include <libcryptosec/pkcs7/Pkcs7Builder.h>

#include <libcryptosec/exception/CertificationException.h>
#include <libcryptosec/Macros.h>

#include <openssl/err.h>

Pkcs7Builder::Pkcs7Builder() :
	pkcs7(PKCS7_new()), p7bio(NULL), state(Pkcs7Builder::NO_INIT), mode(Pkcs7::DATA)
{
	THROW_ENCODE_ERROR_IF(this->pkcs7 == NULL);
}

Pkcs7Builder::~Pkcs7Builder()
{
	if (this->p7bio != NULL) {
		BIO_free(this->p7bio);
		this->p7bio = NULL;
	}

	if (this->pkcs7 != NULL) {
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
	}
}

void Pkcs7Builder::initData()
{
	if (this->state != Pkcs7Builder::NO_INIT) {
		this->reset();
	}

	int rc = PKCS7_set_type(this->pkcs7, NID_pkcs7_data);
	THROW_ENCODE_ERROR_IF(rc == 0);

	this->mode = Pkcs7::DATA;
	this->state = Pkcs7Builder::INIT;
}

void Pkcs7Builder::initDigested(MessageDigest::Algorithm messageDigestAlgorithm, bool attached)
{
	if (this->state != Pkcs7Builder::NO_INIT) {
		this->reset();
	}

	int rc = PKCS7_set_type(this->pkcs7, NID_pkcs7_digest);
	THROW_ENCODE_ERROR_IF(rc == 0);

	rc = PKCS7_content_new(this->pkcs7, NID_pkcs7_data);
	THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
			this->reset();
	);

	const EVP_MD *md = MessageDigest::getMessageDigest(messageDigestAlgorithm);
	rc = PKCS7_set_digest(this->pkcs7, md);
	THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
			this->reset();
	);

	if (!attached) {
		// TODO check error return?
		PKCS7_set_detached(this->pkcs7, 1);
	}

	this->mode = Pkcs7::DIGESTED;
	this->state = Pkcs7Builder::INIT;
}

void Pkcs7Builder::initEncrypted(const SymmetricKey& key, const ByteArray& iv, SymmetricCipher::OperationMode operationMode)
{
	if (this->state != Pkcs7Builder::NO_INIT) {
		this->reset();
	}

	int rc = PKCS7_set_type(this->pkcs7, NID_pkcs7_encrypted);
	THROW_ENCODE_ERROR_IF(rc == 0);

	const EVP_CIPHER *cipher = SymmetricCipher::getCipher(key.getAlgorithm(), operationMode);

	// XXX: PKCS7_set_cipher não funciona com NID_pkcs7_encrypted.
	// O código abaixo foi basado no código do OpenSSL para NID_pkcs7_enveloped.
	// rc = PKCS7_set_cipher(this->pkcs7, cipher);
	// THROW_ENCODE_ERROR_IF(rc == 0);


    int i;
    PKCS7_ENC_CONTENT *ec;

    i = OBJ_obj2nid(this->pkcs7->type);
    THROW_ENCODE_ERROR_AND_FREE_IF(i != NID_pkcs7_encrypted,
    		this->reset();
    );
    ec = this->pkcs7->d.encrypted->enc_data;

    /* Check cipher OID exists and has data in it */
    i = EVP_CIPHER_type(cipher);
    THROW_ENCODE_ERROR_IF(i == NID_undef); // TODO: necssário?

    ec->cipher = cipher;

	ByteArray keyData = key.getEncoded();
	unsigned char *keyDataArray = keyData.getDataPointer();
	unsigned int keyDataSize = keyData.getSize() / 8;

	ByteArray ivData = iv;
	unsigned char *ivDataArray = ivData.getDataPointer();
	unsigned int ivDataSize = ivData.getSize();

	this->p7bio = this->initEncryptedBio(&keyDataArray, &keyDataSize, &ivDataArray, &ivDataSize);

	this->mode = Pkcs7::ENCRYPTED;
	this->state = Pkcs7Builder::INIT;
}

void Pkcs7Builder::initSigned(bool attached)
{
	if (this->state != Pkcs7Builder::NO_INIT) {
		this->reset();
	}

	int rc = PKCS7_set_type(this->pkcs7, NID_pkcs7_signed);
	THROW_ENCODE_ERROR_IF(rc == 0);

	rc = PKCS7_content_new(this->pkcs7, NID_pkcs7_data);
	THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
			this->reset();
	);

	if (!attached) {
		// TODO check error return?
		PKCS7_set_detached(this->pkcs7, 1);
	}

	this->mode = Pkcs7::SIGNED;
	this->state = Pkcs7Builder::INIT;
}

void Pkcs7Builder::initEnveloped(SymmetricKey::Algorithm symmetricAlgorithm,
		SymmetricCipher::OperationMode operationMode)
{
	if (this->state != Pkcs7Builder::NO_INIT) {
		this->reset();
	}

	int rc = PKCS7_set_type(this->pkcs7, NID_pkcs7_enveloped);
	const EVP_CIPHER *cipher = SymmetricCipher::getCipher(symmetricAlgorithm, operationMode);

	rc = PKCS7_set_cipher(this->pkcs7, cipher);
	THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
			this->reset();
	);

	this->mode = Pkcs7::ENVELOPED;
	this->state = Pkcs7Builder::INIT;
}

void Pkcs7Builder::initSignedAndEnveloped(SymmetricKey::Algorithm symmetricAlgorithm,
		SymmetricCipher::OperationMode operationMode)
{
	if (this->state != Pkcs7Builder::NO_INIT) {
		this->reset();
	}

	int rc = PKCS7_set_type(this->pkcs7, NID_pkcs7_signedAndEnveloped);
	const EVP_CIPHER *cipher = SymmetricCipher::getCipher(symmetricAlgorithm, operationMode);

	rc = PKCS7_set_cipher(this->pkcs7, cipher);
	THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
			this->reset();
	);

	this->mode = Pkcs7::SIGNED_AND_ENVELOPED;
	this->state = Pkcs7Builder::INIT;
}

void Pkcs7Builder::addSigner(MessageDigest::Algorithm messageDigestAlgorithm,
		const Certificate& signerCertificate, const PrivateKey& signerPrivateKey)
{
	THROW_ENCODE_ERROR_IF(this->state != Pkcs7Builder::INIT);
	THROW_ENCODE_ERROR_IF(this->mode != Pkcs7::SIGNED && this->mode != Pkcs7::SIGNED_AND_ENVELOPED);

	const X509 *sslCert = signerCertificate.getX509();
	const EVP_PKEY *sslPkey = signerPrivateKey.getEvpPkey();
	const EVP_MD *md = MessageDigest::getMessageDigest(messageDigestAlgorithm);

	// CAST: PKCS7_add_signature não modifica o conteúdo do certificado
	PKCS7_SIGNER_INFO *signerInfo = PKCS7_add_signature(this->pkcs7, (X509*) sslCert, (EVP_PKEY*) sslPkey, md);
	THROW_ENCODE_ERROR_AND_FREE_IF(signerInfo == NULL,
			this->reset();
	);

	// CAST: PKCS7_add_certificate incrementa o contador de refrencias do certificado
	int rc = PKCS7_add_certificate(this->pkcs7, (X509*) sslCert);
	THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
			this->reset();
	);
}

void Pkcs7Builder::addRecipient(const Certificate& certificate)
{
	THROW_ENCODE_ERROR_IF(this->state != Pkcs7Builder::INIT);
	THROW_ENCODE_ERROR_IF(this->mode != Pkcs7::ENVELOPED && this->mode != Pkcs7::SIGNED && this->mode != Pkcs7::SIGNED_AND_ENVELOPED);

	const X509 *sslCertificate = certificate.getX509();

	// CAST: PKCS7_add_recipient não modifica o certificado
	PKCS7_RECIP_INFO *recipInfo = PKCS7_add_recipient(this->pkcs7, (X509*) sslCertificate);
	THROW_ENCODE_ERROR_AND_FREE_IF(recipInfo == NULL,
			this->reset();
	);
}

void Pkcs7Builder::addCertificate(const Certificate& certificate)
{
	THROW_ENCODE_ERROR_IF(this->state != Pkcs7Builder::INIT && this->state != Pkcs7Builder::UPDATE);
	THROW_ENCODE_ERROR_IF(this->mode != Pkcs7::ENVELOPED && this->mode != Pkcs7::SIGNED && this->mode != Pkcs7::SIGNED_AND_ENVELOPED);

	const X509 *sslCertificate = certificate.getX509();

	// CAST: PKCS7_add_certificate incrementa o contador de refrencias do certificado
	int rc = PKCS7_add_certificate(this->pkcs7, (X509*) sslCertificate);
	THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
			this->reset();
	);
}

void Pkcs7Builder::addCrl(const CertificateRevocationList& crl)
{
	THROW_ENCODE_ERROR_IF(this->state != Pkcs7Builder::INIT && this->state != Pkcs7Builder::UPDATE);
	THROW_ENCODE_ERROR_IF(this->mode != Pkcs7::ENVELOPED && this->mode != Pkcs7::SIGNED && this->mode != Pkcs7::SIGNED_AND_ENVELOPED);

	const X509_CRL *sslCrl = crl.getX509Crl();

	// CAST: PKCS7_add_crl incrementa o contador de refrencias da CRL
	int rc = PKCS7_add_crl(this->pkcs7, (X509_CRL*) sslCrl);
	THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
			this->reset();
	);
}

void Pkcs7Builder::update(const std::string& data)
{
	this->update((const unsigned char*) data.c_str(), data.size());
}

void Pkcs7Builder::update(const ByteArray& data)
{
	this->update(data.getConstDataPointer(), data.getSize());
}

void Pkcs7Builder::update(const unsigned char* data, unsigned int size)
{
	THROW_ENCODE_ERROR_IF(this->state != Pkcs7Builder::INIT && this->state != Pkcs7Builder::UPDATE);

	int nid = OBJ_obj2nid(this->pkcs7->type);

	// Do not move this code to Pkcs7Builder::initX.
	// PKCS7_dataInit MUST be called after setSigner, setRecipient,
	// setCertificate and setCrl, what we expect to be done after
	// Pkcs7Builder::initX.
	// PKCS7_dataInit doesn't work for NID_pkcs7_encrypted.
	if (this->state == Pkcs7Builder::INIT && nid != NID_pkcs7_encrypted) {
		this->p7bio = PKCS7_dataInit(this->pkcs7, NULL);
		THROW_ENCODE_ERROR_AND_FREE_IF(this->p7bio == NULL,
				this->reset();
		);
	}

	int writtenBytes = BIO_write(this->p7bio, data, size);
	THROW_ENCODE_ERROR_AND_FREE_IF((unsigned int) writtenBytes != size,
			this->reset();
	);
	// CAST: TODO: check cast

	this->state = Pkcs7Builder::UPDATE;
}

Pkcs7 Pkcs7Builder::doFinal()
{
	THROW_ENCODE_ERROR_IF(this->state != Pkcs7Builder::UPDATE);

	int rc = BIO_flush(this->p7bio);
	THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
			this->reset();
	);

	// XXX: OpenSSL doesn't support NID_pkcs7_encrypted
	// So, we copied the PKCS7_dataFinal for NID_pkcs7_enveloped
	// removing the key management code.
	if (OBJ_obj2nid(this->pkcs7->type) == NID_pkcs7_encrypted) {
		BIO *btmp;
		ASN1_OCTET_STRING *os = NULL;

		// TODO: necessário?
		THROW_ENCODE_ERROR_AND_FREE_IF(this->pkcs7 == NULL,
				this->reset();
		);

		THROW_ENCODE_ERROR_AND_FREE_IF(this->pkcs7->d.ptr == NULL,
				this->reset();
		);

		int i = OBJ_obj2nid(this->pkcs7->type);
		this->pkcs7->state = PKCS7_S_HEADER;

		THROW_ENCODE_ERROR_AND_FREE_IF(i != NID_pkcs7_encrypted,
				this->reset();
		);

		os = this->pkcs7->d.encrypted->enc_data->enc_data;
		if (os == NULL) {
			os = ASN1_OCTET_STRING_new();
			THROW_ENCODE_ERROR_AND_FREE_IF(os == NULL,
					this->reset();
			);

			this->pkcs7->d.encrypted->enc_data->enc_data = os;
		}

		if (!PKCS7_is_detached(this->pkcs7)) {
			/*
			 * NOTE(emilia): I think we only reach os == NULL here because detached
			 * digested data support is broken.
			 */
			THROW_ENCODE_ERROR_AND_FREE_IF(os == NULL,
					this->reset();
			);

			if (!(os->flags & ASN1_STRING_FLAG_NDEF)) {
				char *cont;
				long contlen;
				btmp = BIO_find_type(this->p7bio, BIO_TYPE_MEM);
				THROW_ENCODE_ERROR_AND_FREE_IF(btmp == NULL,
						this->reset();
				);
				contlen = BIO_get_mem_data(btmp, &cont);
				/*
				 * Mark the BIO read only then we can use its copy of the data
				 * instead of making an extra copy.
				 */
				BIO_set_flags(btmp, BIO_FLAGS_MEM_RDONLY);
				BIO_set_mem_eof_return(btmp, 0);
				ASN1_STRING_set0(os, (unsigned char *)cont, contlen);
			}
		}
	} else {
		rc = PKCS7_dataFinal(this->pkcs7, this->p7bio);
		const char *file;
		int line;
		ERR_get_error_line(&file, &line);
		THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
				this->reset();
		);
	}

	Pkcs7 ret(this->pkcs7);

	// keep this order to prevent reset from freeing this->pkcs7
	this->pkcs7 = NULL;
	this->reset();

	return ret;
}

Pkcs7 Pkcs7Builder::doFinal(const std::string& data)
{
	return this->doFinal((const unsigned char*) data.c_str(), data.size());
}

Pkcs7 Pkcs7Builder::doFinal(const ByteArray& data)
{
	return this->doFinal(data.getConstDataPointer(), data.getSize());
}

Pkcs7 Pkcs7Builder::doFinal(const unsigned char* data, unsigned int size)
{
	this->update(data, size);
	return this->doFinal();
}

void Pkcs7Builder::doFinal(std::istream *in, std::ostream *out)
{
	char *data = NULL;
	int size, rc;
	int maxSize = 1024;

	// TODO: porque não funciona com update?
	THROW_ENCODE_ERROR_IF(this->state == Pkcs7Builder::INIT);

	ByteArray buf(maxSize);
	while ((size = in->readsome((char *) buf.getDataPointer(), maxSize)) > 0) {
		buf.setSize(size);
		this->update(buf);
	}

	THROW_ENCODE_ERROR_AND_FREE_IF(this->state != Pkcs7Builder::UPDATE,
			this->reset();
	);

	rc = BIO_flush(this->p7bio);
	THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0 || rc == -1,
			this->reset();
	);

	rc = PKCS7_dataFinal(this->pkcs7, this->p7bio);
	THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
			this->reset();
	);

	BIO *buffer = BIO_new(BIO_s_mem());
	THROW_ENCODE_ERROR_AND_FREE_IF(buffer == NULL,
			this->reset();
	);

	int wrote = PEM_write_bio_PKCS7(buffer, this->pkcs7);
	THROW_ENCODE_ERROR_AND_FREE_IF(wrote == 0,
			BIO_free(buffer);
			this->reset();
	);

	int ndata = BIO_get_mem_data(buffer, &data);
	THROW_ENCODE_ERROR_AND_FREE_IF(ndata <= 0,
			BIO_free(buffer);
			this->reset();
	);

	out->write(data, ndata);

	this->reset();
}

void Pkcs7Builder::reset()
{
	this->state = Pkcs7Builder::NO_INIT;

	if (this->p7bio != NULL) {
		BIO_free(this->p7bio);
		this->p7bio = NULL;
	}

	if (this->pkcs7 != NULL) {
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
	}

	this->pkcs7 = PKCS7_new();
	THROW_ENCODE_ERROR_IF(this->pkcs7 == NULL);
}

BIO* Pkcs7Builder::initEncryptedBio(unsigned char** key, unsigned int *key_size, unsigned char** iv, unsigned int *iv_size) {
	int rc;
	BIO *out = NULL, *btmp = NULL;
	const EVP_CIPHER *evp_cipher = NULL;
	X509_ALGOR *xalg = NULL;

	THROW_ENCODE_ERROR_IF(this->pkcs7->d.ptr == NULL);
	THROW_ENCODE_ERROR_IF(OBJ_obj2nid(this->pkcs7->type) != NID_pkcs7_encrypted);
	THROW_ENCODE_ERROR_IF(key == NULL || key_size == NULL || iv == NULL || iv_size == NULL);

	this->pkcs7->state = PKCS7_S_HEADER;
    xalg = this->pkcs7->d.encrypted->enc_data->algorithm;
	evp_cipher = this->pkcs7->d.encrypted->enc_data->cipher;
	THROW_ENCODE_ERROR_IF(evp_cipher == NULL);

	unsigned int keylen, ivlen;
	EVP_CIPHER_CTX *ctx;

	btmp = BIO_new(BIO_f_cipher());
	THROW_ENCODE_ERROR_IF(btmp == NULL);

	BIO_get_cipher_ctx(btmp, &ctx);
	keylen = EVP_CIPHER_key_length(evp_cipher);
	ivlen = EVP_CIPHER_iv_length(evp_cipher);

	bool generateKey = (*key == NULL);
	if (generateKey) {
		*key = new unsigned char[keylen];
		*key_size = keylen;
	} else {
		THROW_ENCODE_ERROR_AND_FREE_IF((*key_size) != keylen,
				BIO_free_all(btmp);
		);
	}

	if (*iv == NULL) {
		*iv = new unsigned char[ivlen];
		*iv_size = ivlen;
		if (ivlen > 0) {
			rc = RAND_bytes(*iv, ivlen);
			THROW_ENCODE_ERROR_IF(rc <= 0);
		}
	} else {
		THROW_ENCODE_ERROR_AND_FREE_IF((*iv_size) != ivlen,
				BIO_free_all(btmp);
		);
	}

	xalg->algorithm = OBJ_nid2obj(EVP_CIPHER_type(evp_cipher));
	rc = EVP_CipherInit_ex(ctx, evp_cipher, NULL, NULL, NULL, 1);
	THROW_ENCODE_ERROR_AND_FREE_IF(rc <= 0,
			BIO_free_all(btmp);
	);

	if (generateKey) {
		rc = EVP_CIPHER_CTX_rand_key(ctx, *key);
		THROW_ENCODE_ERROR_AND_FREE_IF(rc <= 0,
				BIO_free_all(btmp);
		);
	}

	rc = EVP_CipherInit_ex(ctx, NULL, NULL, *key, *iv, 1);
	THROW_ENCODE_ERROR_AND_FREE_IF(rc <= 0,
			BIO_free_all(btmp);
	);

	if (ivlen > 0) {
		if (xalg->parameter == NULL) {
			xalg->parameter = ASN1_TYPE_new();
			THROW_ENCODE_ERROR_AND_FREE_IF(xalg->parameter == NULL,
					BIO_free_all(btmp);
			);
		}

		rc = EVP_CIPHER_param_to_asn1(ctx, xalg->parameter);
		THROW_ENCODE_ERROR_AND_FREE_IF(rc < 0,
				BIO_free_all(btmp);
		);
	}

	OPENSSL_cleanse(key, keylen);

	out = btmp;
	btmp = NULL;
	BIO *bio = NULL;

	if (PKCS7_is_detached(this->pkcs7)) {
		bio = BIO_new(BIO_s_null());
	} else {
		bio = BIO_new(BIO_s_mem());
		THROW_ENCODE_ERROR_AND_FREE_IF(bio == NULL,
				BIO_free_all(out);
		);
		BIO_set_mem_eof_return(bio, 0);
	}

	THROW_ENCODE_ERROR_AND_FREE_IF(bio == NULL,
			BIO_free_all(out);
	);

	BIO_push(out, bio);

	return out;
}

