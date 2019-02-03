#include <libcryptosec/pkcs7/Pkcs7SignedDataBuilder.h>

#include <libcryptosec/exception/OperationException.h>
#include <libcryptosec/Macros.h>

Pkcs7SignedDataBuilder::Pkcs7SignedDataBuilder(
		MessageDigest::Algorithm messageDigestAlgorithm,
		const Certificate& signerCertificate,
		const PrivateKey& signerPrivateKey,
		bool attached)
{
	this->init(messageDigestAlgorithm, signerCertificate, signerPrivateKey, attached);
}

Pkcs7SignedDataBuilder::~Pkcs7SignedDataBuilder()
{
}

void Pkcs7SignedDataBuilder::init(
		MessageDigest::Algorithm messageDigestAlgorithm,
		const Certificate& signerCertificate,
		const PrivateKey& signerPrivateKey,
		bool attached)
{
	if (this->state != Pkcs7Builder::NO_INIT) {
		this->reset();
	}

	int rc = PKCS7_set_type(this->pkcs7, NID_pkcs7_signed);
	THROW_OPERATION_ERROR_IF(rc == 0);

	rc = PKCS7_content_new(this->pkcs7, NID_pkcs7_data);
	THROW_OPERATION_ERROR_IF(rc == 0);

	if (!attached) {
		// TODO check error return?
		PKCS7_set_detached(this->pkcs7, 1);
	}

	// Keep this order, addSigner fails if state != INIT
	this->state = Pkcs7Builder::INIT;
	this->addSigner(messageDigestAlgorithm, signerCertificate, signerPrivateKey);
}

void Pkcs7SignedDataBuilder::addSigner(
		MessageDigest::Algorithm messageDigestAlgorithm,
		const Certificate& signerCertificate,
		const PrivateKey& signerPrivateKey)
{
	int rc;
	THROW_OPERATION_ERROR_IF(this->state != Pkcs7Builder::INIT);

	const X509 *sslCert = signerCertificate.getX509();
	const EVP_PKEY *sslPkey = signerPrivateKey.getEvpPkey();
	const EVP_MD *md = MessageDigest::getMessageDigest(messageDigestAlgorithm);

	// CAST: PKCS7_add_signature não modifica o conteúdo do certificado
	PKCS7_SIGNER_INFO *signerInfo = PKCS7_add_signature(this->pkcs7, (X509*) sslCert, (EVP_PKEY*) sslPkey, md);
	THROW_OPERATION_ERROR_AND_FREE_IF(signerInfo == NULL,
			this->reset();
	);

	// CAST: PKCS7_add_certificate incrementa o contador de refrencias do certificado
	rc = PKCS7_add_certificate(this->pkcs7, (X509*) sslCert);
	THROW_OPERATION_ERROR_AND_FREE_IF(rc == 0,
			this->reset();
	);
}

void Pkcs7SignedDataBuilder::addCertificate(const Certificate& certificate)
{
	THROW_OPERATION_ERROR_IF(this->state != Pkcs7Builder::INIT && this->state != Pkcs7Builder::UPDATE);

	const X509 *sslCertificate = certificate.getX509();

	// CAST: PKCS7_add_certificate incrementa o contador de refrencias do certificado
	int rc = PKCS7_add_certificate(this->pkcs7, (X509*) sslCertificate);
	THROW_OPERATION_ERROR_AND_FREE_IF(rc == 0,
			this->reset();
	);
}

void Pkcs7SignedDataBuilder::addCrl(const CertificateRevocationList& crl)
{
	THROW_OPERATION_ERROR_IF(this->state != Pkcs7Builder::INIT && this->state != Pkcs7Builder::UPDATE);

	const X509_CRL *sslCrl = crl.getX509Crl();

	// CAST: PKCS7_add_crl incrementa o contador de refrencias da CRL
	int rc = PKCS7_add_crl(this->pkcs7, (X509_CRL*) sslCrl);
	THROW_OPERATION_ERROR_AND_FREE_IF(rc == 0,
			this->reset();
	);
}

Pkcs7SignedData Pkcs7SignedDataBuilder::doFinal()
{
	THROW_OPERATION_ERROR_IF(this->state != Pkcs7Builder::UPDATE);

	int rc = BIO_flush(this->p7bio);
	THROW_OPERATION_ERROR_AND_FREE_IF(rc == 0,
			this->reset();
	);

	rc = PKCS7_dataFinal(this->pkcs7, this->p7bio);
	THROW_OPERATION_ERROR_AND_FREE_IF(rc == 0,
			this->reset();
	);
	
	Pkcs7SignedData ret(this->pkcs7);
	this->pkcs7 = NULL;
	this->reset();

	return ret;
}

Pkcs7SignedData Pkcs7SignedDataBuilder::doFinal(const std::string& data)
{
	this->update(data);
	return this->doFinal();
}

Pkcs7SignedData Pkcs7SignedDataBuilder::doFinal(const ByteArray& data)
{
	this->update(data);
	return this->doFinal();
}
