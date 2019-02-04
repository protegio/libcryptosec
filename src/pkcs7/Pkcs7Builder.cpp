#include <libcryptosec/pkcs7/Pkcs7Builder.h>

#include <libcryptosec/exception/CertificationException.h>
#include <libcryptosec/Macros.h>

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

	this->state = Pkcs7Builder::INIT;
}

void Pkcs7Builder::initDigest(MessageDigest::Algorithm messageDigestAlgorithm, bool attached)
{
	if (this->state != Pkcs7Builder::NO_INIT) {
		this->reset();
	}

	int rc = PKCS7_set_type(this->pkcs7, NID_pkcs7_digest);
	THROW_ENCODE_ERROR_IF(rc == 0);

	rc = PKCS7_content_new(this->pkcs7, NID_pkcs7_data);
	THROW_ENCODE_ERROR_IF(rc == 0);

	if (!attached) {
		// TODO check error return?
		PKCS7_set_detached(this->pkcs7, 1);
	}

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
	THROW_ENCODE_ERROR_IF(rc == 0);

	if (!attached) {
		// TODO check error return?
		PKCS7_set_detached(this->pkcs7, 1);
	}

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

	rc = PKCS7_set_cipher(pkcs7, cipher);
	THROW_ENCODE_ERROR_IF(rc == 0);

	this->state = Pkcs7Builder::INIT;
}

void Pkcs7Builder::addSigner(MessageDigest::Algorithm messageDigestAlgorithm,
		const Certificate& signerCertificate, const PrivateKey& signerPrivateKey)
{
	THROW_ENCODE_ERROR_IF(this->state != Pkcs7Builder::INIT);
	THROW_ENCODE_ERROR_IF(this->mode != Pkcs7::ENVELOPED && this->mode != Pkcs7::SIGNED && this->mode != Pkcs7::SIGNED_AND_ENVELOPED);

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
	this->update((const unsigned char*) data.c_str(), data.size() + 1);
}

void Pkcs7Builder::update(const ByteArray& data)
{
	this->update(data.getConstDataPointer(), data.getSize());
}

void Pkcs7Builder::update(const unsigned char* data, unsigned int size)
{
	THROW_ENCODE_ERROR_IF(this->state != Pkcs7Builder::INIT && this->state != Pkcs7Builder::UPDATE);

	if (this->state == Pkcs7Builder::INIT) {
		this->p7bio = PKCS7_dataInit(this->pkcs7, NULL);
		THROW_ENCODE_ERROR_AND_FREE_IF(this->p7bio == NULL,
				this->reset();
		);
	}

	int rc = BIO_write(this->p7bio, data, size);
	THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
			this->reset();
	);

	this->state = Pkcs7Builder::UPDATE;
}

Pkcs7 Pkcs7Builder::doFinal()
{
	THROW_ENCODE_ERROR_IF(this->state != Pkcs7Builder::UPDATE);

	int rc = BIO_flush(this->p7bio);
	THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
			this->reset();
	);

	rc = PKCS7_dataFinal(this->pkcs7, this->p7bio);
	THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
			this->reset();
	);

	Pkcs7 ret(this->pkcs7);

	// keep this order to prevent reset from freeing this->pkcs7
	this->pkcs7 = NULL;
	this->reset();

	return ret;
}

Pkcs7 Pkcs7Builder::doFinal(const std::string& data)
{
	return this->doFinal((const unsigned char*) data.c_str(), data.size() + 1);
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
		this->pkcs7 = PKCS7_new();
		THROW_ENCODE_ERROR_IF(this->pkcs7 == NULL);
	}
}
