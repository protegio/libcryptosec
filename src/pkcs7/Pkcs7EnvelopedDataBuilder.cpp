#include <libcryptosec/pkcs7/Pkcs7EnvelopedDataBuilder.h>

#include <libcryptosec/certificate/Certificate.h>
#include <libcryptosec/ByteArray.h>
#include <libcryptosec/exception/OperationException.h>
#include <libcryptosec/Macros.h>

Pkcs7EnvelopedDataBuilder::Pkcs7EnvelopedDataBuilder(
		const Certificate& cert,
		SymmetricKey::Algorithm symAlgorithm,
		SymmetricCipher::OperationMode symOperationMode)
{
	this->init(cert, symAlgorithm, symOperationMode);
}

Pkcs7EnvelopedDataBuilder::~Pkcs7EnvelopedDataBuilder()
{
}

void Pkcs7EnvelopedDataBuilder::init(
		const Certificate& cert,
		SymmetricKey::Algorithm symAlgorithm,
		SymmetricCipher::OperationMode symOperationMode)
{
	if (this->state != Pkcs7Builder::NO_INIT) {
		this->reset();
	}

	int rc = PKCS7_set_type(this->pkcs7, NID_pkcs7_enveloped);
	const EVP_CIPHER *cipher = SymmetricCipher::getCipher(symAlgorithm, symOperationMode);

	rc = PKCS7_set_cipher(pkcs7, cipher);
	THROW_OPERATION_ERROR_IF(rc == 0);

	// CAST: PKCS7_add_recipient não modifica o certificado
	PKCS7_RECIP_INFO *recipInfo = PKCS7_add_recipient(this->pkcs7, (X509*) cert.getX509());
	THROW_OPERATION_ERROR_IF(recipInfo == NULL);

	this->state = Pkcs7Builder::INIT;
}

void Pkcs7EnvelopedDataBuilder::addCipher(const Certificate& certificate)
{
	THROW_OPERATION_ERROR_IF(this->state != Pkcs7Builder::INIT);

	// CAST: PKCS7_add_recipient não modifica o certificado
	PKCS7_RECIP_INFO *recipInfo = PKCS7_add_recipient(this->pkcs7, (X509*) certificate.getX509());
	THROW_OPERATION_ERROR_AND_FREE_IF(recipInfo == NULL,
			this->reset();
	);
}

Pkcs7EnvelopedData Pkcs7EnvelopedDataBuilder::doFinal()
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

	Pkcs7EnvelopedData ret(this->pkcs7);
	this->pkcs7 = NULL;
	this->reset();
	return ret;
}

Pkcs7EnvelopedData Pkcs7EnvelopedDataBuilder::doFinal(const std::string& data)
{
	this->update(data);
	return this->doFinal();
}

Pkcs7EnvelopedData Pkcs7EnvelopedDataBuilder::doFinal(const ByteArray& data)
{
	this->update(data);
	return this->doFinal();
}
