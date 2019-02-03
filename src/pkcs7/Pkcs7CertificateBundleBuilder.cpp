#include <libcryptosec/pkcs7/Pkcs7CertificateBundleBuilder.h>

#include <libcryptosec/exception/OperationException.h>
#include <libcryptosec/Macros.h>

Pkcs7CertificateBundleBuilder::Pkcs7CertificateBundleBuilder() :
		Pkcs7Builder()
{
	this->state = Pkcs7Builder::INIT;

	int rc = PKCS7_set_type(this->pkcs7, NID_pkcs7_signed);
	THROW_OPERATION_ERROR_IF(rc == 0);

	rc = PKCS7_content_new(this->pkcs7, NID_pkcs7_data);
	THROW_OPERATION_ERROR_IF(rc == 0);
}

Pkcs7CertificateBundleBuilder::~Pkcs7CertificateBundleBuilder()
{
}

void Pkcs7CertificateBundleBuilder::init()
{
	if (this->state != Pkcs7Builder::NO_INIT)
	{
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
		if (this->state == Pkcs7Builder::UPDATE)
		{
			BIO_free(this->p7bio);
			this->p7bio = NULL;
		}
	}

	this->state = Pkcs7Builder::INIT;
	PKCS7_set_type(this->pkcs7, NID_pkcs7_signed);
	PKCS7_content_new(this->pkcs7, NID_pkcs7_data);
}

void Pkcs7CertificateBundleBuilder::addCertificate(const Certificate &cert)
{
	THROW_OPERATION_ERROR_IF(this->state != Pkcs7Builder::INIT && this->state != Pkcs7Builder::UPDATE);
	this->certificates.push_back(cert);
}

Pkcs7CertificateBundle Pkcs7CertificateBundleBuilder::doFinal() const
{
	THROW_OPERATION_ERROR_IF(this->state != Pkcs7Builder::INIT && this->state != Pkcs7Builder::UPDATE);

	// Prepara a stack de certificados que será inserida no PKCS7
	STACK_OF(X509) *sslCerts = sk_X509_new_null();
	for (auto certificate : this->certificates) {
		X509 *sslCert = certificate.getSslObject();
		int rc = sk_X509_push(sslCerts, sslCert);
	}

	// Cria o pacotes PKCS7 com a stack de certificados
	PKCS7 *pkcs7 = PKCS7_sign(NULL, NULL, sslCerts, this->p7bio, 0);
	sk_X509_pop_free(sslCerts, X509_free);
	THROW_OPERATION_ERROR_IF(pkcs7 == NULL);

	Pkcs7CertificateBundle ret(pkcs7);

	return ret;
}
