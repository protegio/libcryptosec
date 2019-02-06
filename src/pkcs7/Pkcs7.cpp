#include <libcryptosec/pkcs7/Pkcs7.h>

#include <openssl/rand.h>

CertPathValidatorResult Pkcs7::cpvr;

Pkcs7::Pkcs7(PKCS7* pkcs7)
{
	this->pkcs7 = pkcs7;
}

Pkcs7::Pkcs7(const PKCS7* pkcs7) :
		pkcs7(PKCS7_dup((PKCS7*) pkcs7))
{
	THROW_DECODE_ERROR_IF(this->pkcs7 == NULL);
}

Pkcs7::Pkcs7(const std::string& pemEncoded)
{
	DECODE_PEM(this->pkcs7, pemEncoded, PEM_read_bio_PKCS7);
}

Pkcs7::Pkcs7(const ByteArray& derEncoded)
{
	DECODE_DER(this->pkcs7, derEncoded, d2i_PKCS7_bio);
}

Pkcs7::Pkcs7(const Pkcs7& pkcs7) :
		pkcs7(PKCS7_dup(pkcs7.pkcs7))
{
	THROW_DECODE_ERROR_IF(this->pkcs7 == NULL);
}

Pkcs7::Pkcs7(Pkcs7&& pkcs7) :
		pkcs7(std::move(pkcs7.pkcs7))
{
	pkcs7.pkcs7 = NULL;
}

Pkcs7::~Pkcs7()
{
	if (this->pkcs7 != NULL) {
		PKCS7_free(this->pkcs7);
	}
}

Pkcs7& Pkcs7::operator=(const Pkcs7& pkcs7)
{
	if (&pkcs7 == this) {
		return *this;
	}

	PKCS7 *sslObject = PKCS7_dup(pkcs7.pkcs7);
	THROW_DECODE_ERROR_IF(sslObject == NULL);

	if (this->pkcs7 != NULL) {
		PKCS7_free(this->pkcs7);
	}

	this->pkcs7 = sslObject;

	return *this;
}

Pkcs7& Pkcs7::operator=(Pkcs7&& pkcs7)
{
	if (&pkcs7 == this) {
		return *this;
	}

	if (this->pkcs7 != NULL) {
		PKCS7_free(this->pkcs7);
	}

	this->pkcs7 = pkcs7.pkcs7;
	pkcs7.pkcs7 = NULL;

	return *this;
}

Pkcs7::Type Pkcs7::getType() const
{
	int nid = OBJ_obj2nid(this->pkcs7->type);
	switch (nid) {
	case NID_pkcs7_signed:
		return Pkcs7::Type::SIGNED;
	case NID_pkcs7_enveloped:
		return Pkcs7::Type::ENVELOPED;
	case NID_pkcs7_signedAndEnveloped:
		return Pkcs7::Type::SIGNED_AND_ENVELOPED;
	case NID_pkcs7_encrypted:
		return Pkcs7::Type::ENCRYPTED;
	case NID_pkcs7_digest:
		return Pkcs7::Type::DIGESTED;
	case NID_pkcs7_data:
		return Pkcs7::Type::DATA;
	default:
		THROW_DECODE_ERROR_IF(true);
	}
}

std::string Pkcs7::getPemEncoded() const
{
	ENCODE_PEM_AND_RETURN(this->pkcs7, PEM_write_bio_PKCS7);
}

ByteArray Pkcs7::getDerEncoded() const
{
	ENCODE_DER_AND_RETURN(this->pkcs7, i2d_PKCS7_bio);
}

void Pkcs7::extract(std::ostream& out)
{
	// TODO: não encontramos uma forma padrão de extrair os dados de um PKCS7 do tipo DATA.
	// PKCS7_dataInit e PKCS7_dataFinal aparentemente deveriam funcionar, mas o BIO retornado
	// sempre retorna 0 bytes lidos na chamada BIO_read.
	if (this->getType() == Pkcs7::Type::DATA) {
		out.write((const char*) this->pkcs7->d.data->data, this->pkcs7->d.data->length);
		return;
	}

	BIO *p7bio = PKCS7_dataInit(this->pkcs7, NULL);
	THROW_DECODE_ERROR_IF(p7bio == NULL);

	// TODO: 1KB pode ser muito para um sistema embarcado
	int maxSize = 1024;
	int size;
	char buf[maxSize];

	do {
		// TODO: A documentação do OPENSSL diz que BIO_read pode retornar 0
		// ou -1 para indicar que não há dados para serem lidos AGORA e não
		// necessariamente por causa de um erro. Aqui nós tratamos sempre como
		// fim dos daos e finalizamos a extração. Talvez, o correto fosse verificar
		// se chegou em um null terminator ou algo parecido.
		size = BIO_read(p7bio, buf, maxSize);
		if (size == 0 || size == -1) break;
		out.write(buf, size);
	} while (size == maxSize);

	BIO_free(p7bio);
}

void Pkcs7::decrypt(const Certificate& certificate, const PrivateKey& privateKey, std::ostream& out)
{
	const EVP_PKEY *sslPkey = privateKey.getEvpPkey();
	const X509 *sslCertificate = certificate.getX509();

	// CAST: PKCS7_dataDecode não modifica o certificado
	// CAST: PKCS7_dataDecode não modifica a chave privada
	BIO *p7bio = PKCS7_dataDecode(this->pkcs7, (EVP_PKEY*) sslPkey, NULL, (X509*) sslCertificate);
	THROW_DECODE_ERROR_IF(p7bio == NULL);

	// TODO: 1KB pode ser muito para sistemas embarcados.
	int maxSize = 1024;
	int size;
	char buf[maxSize];

	do {
		// TODO: A documentação do OPENSSL diz que BIO_read pode retornar 0
		// ou -1 para indicar que não há dados para serem lidos AGORA e não
		// necessariamente por causa de um erro. Aqui nós tratamos sempre como
		// fim dos daos e finalizamos a extração. Talvez, o correto fosse verificar
		// se chegou em um null terminator ou algo parecido.
		size = BIO_read(p7bio, buf, maxSize);
		if (size == 0 || size == -1) break;
		out.write(buf, size);
	} while (size == maxSize);

	BIO_free(p7bio);
}

bool Pkcs7::verify(
		bool checkSignerCert,
		const vector<Certificate>& trustedCerts,
		CertPathValidatorResult **cpvr,
		const vector<ValidationFlags>& vflags)
{
	BIO *p7bio;
	bool ret;
	int rc;
	int flags = 0;
	X509_STORE *store = NULL;
	STACK_OF(X509) *certs = NULL;

	// TODO: colocar no init?
	ERR_load_crypto_strings();

	if(checkSignerCert) {
		int nid = OBJ_obj2nid(this->pkcs7->type);
		switch (nid) {
			case NID_pkcs7_signed:
				certs = this->pkcs7->d.sign->cert;
				break;

			case NID_pkcs7_signedAndEnveloped:
				certs = this->pkcs7->d.signed_and_enveloped->cert;
				break;

			default:
				THROW_DECODE_ERROR_IF(true);
		}

		// instancia store de certificados
		store = X509_STORE_new();
		THROW_DECODE_ERROR_IF(store == NULL);

		// define funcao de callback
		X509_STORE_set_verify_cb_func(store, Pkcs7::callback);

		// define certificados confiaveis
		for(auto certificate : trustedCerts) {
			const X509 *sslCert = certificate.getX509();
			// CAST: X509_STORE_add_cert não modifica sslCert
			rc = X509_STORE_add_cert(store, (X509*) sslCert);
			THROW_DECODE_ERROR_AND_FREE_IF(rc == 0,
					X509_STORE_free(store);
			);
		}

		//define flags
		for(auto vflag : vflags) {
			switch(vflag) {
				case CRL_CHECK:
					rc = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
					THROW_DECODE_ERROR_AND_FREE_IF(rc == 0,
							X509_STORE_free(store);
					);
					break;

				case CRL_CHECK_ALL:
					/*precisa por CRL_CHECK tambem, caso contrario o openssl nao verifica CRL*/
					rc = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
					THROW_DECODE_ERROR_AND_FREE_IF(rc == 0,
							X509_STORE_free(store);
					);

					rc = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK_ALL);
					THROW_DECODE_ERROR_AND_FREE_IF(rc == 0,
							X509_STORE_free(store);
					);
					break;
			}
		}
	} else {
		flags = PKCS7_NOVERIFY;
	}

	p7bio = PKCS7_dataInit(this->pkcs7, NULL);
	THROW_DECODE_ERROR_AND_FREE_IF(p7bio == NULL,
			if (store != NULL) {
				X509_STORE_free(store);
			}
	);

	rc = PKCS7_verify(this->pkcs7, certs, store, p7bio, NULL, flags);
	if (rc == 1) {
		ret = true;
	} else {
		// this case can be a error
		ret = false;
		if(cpvr) {
			*cpvr = new CertPathValidatorResult(Pkcs7::cpvr);
		}
	}

	/* desaloca estruturas */
	BIO_free(p7bio);

	if (store != NULL) {
		X509_STORE_free(store);
	}

	return ret;
}

bool Pkcs7::verifyAndExtract(
		std::ostream& out,
		bool checkSignerCert,
		const vector<Certificate>& trusted,
		CertPathValidatorResult** cpvr,
		const vector<ValidationFlags>& flags)
{
	bool ret = this->verify(checkSignerCert, trusted, cpvr, flags);

	BIO *p7bio = PKCS7_dataInit(this->pkcs7, NULL);
	THROW_DECODE_ERROR_IF(p7bio == NULL);

	int size;
	int maxSize = 1024;
	char buf[maxSize];

	do {
		// TODO: A documentação do OPENSSL diz que BIO_read pode retornar 0
		// ou -1 para indicar que não há dados para serem lidos AGORA e não
		// necessariamente por causa de um erro. Aqui nós tratamos sempre como
		// fim dos daos e finalizamos a extração. Talvez, o correto fosse verificar
		// se chegou em um null terminator ou algo parecido.
		size = BIO_read(p7bio, buf, maxSize);
		if (size == 0 || size == -1) break;
		out.write(buf, size);
	} while (size == maxSize);

	BIO_free(p7bio);

	return ret;
}

int Pkcs7::callback(int ok, X509_STORE_CTX *ctx)
{
	if (!ok) {
		const X509* sslCert = X509_STORE_CTX_get_current_cert(ctx);
		if (sslCert != NULL) {
			Certificate *cert = new Certificate(sslCert);
			Pkcs7::cpvr.setInvalidCertificate(cert);
			delete cert;
		}

		int error = X509_STORE_CTX_get_error(ctx);

		int depth = X509_STORE_CTX_get_error_depth(ctx);
		CertPathValidatorResult::ErrorCode errorCode = CertPathValidatorResult::long2ErrorCode(error);

		Pkcs7::cpvr.setDepth(depth);
		Pkcs7::cpvr.setErrorCode(errorCode);

		if (error == X509_V_ERR_CERT_HAS_EXPIRED) ok = 1;

		// since we are just checking the certificates, it is ok
		// if they are self signed. But we should still warn the user
		if (error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) ok = 1;

		//Continue after extension errors too
		if (error == X509_V_ERR_INVALID_CA) ok = 1;
		if (error == X509_V_ERR_INVALID_NON_CA) ok = 1;
		if (error == X509_V_ERR_PATH_LENGTH_EXCEEDED) ok = 1;
		if (error == X509_V_ERR_INVALID_PURPOSE) ok = 1;
		if (error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) ok = 1;
		if (error == X509_V_ERR_CRL_HAS_EXPIRED) ok = 1;
		if (error == X509_V_ERR_CRL_NOT_YET_VALID) ok = 1;
		if (error == X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION) ok = 1;
		//TODO incluir informacoes de erro de politicas na classe CertPathValidatorResult
	}

	return ok;
}

std::vector<Certificate> Pkcs7::getCertificates() const
{
	std::vector<Certificate> ret;
	int num = sk_X509_num(this->pkcs7->d.sign->cert);
	for (int i = 0; i < num; i++) {
		const X509 *oneCertificate = sk_X509_value(this->pkcs7->d.sign->cert, i);
		THROW_DECODE_ERROR_IF(oneCertificate == NULL);

		Certificate certificate(oneCertificate);
		ret.push_back(std::move(certificate));
	}
	return ret;
}

std::vector<CertificateRevocationList> Pkcs7::getCrls() const
{
	std::vector<CertificateRevocationList> ret;
	int num = sk_X509_CRL_num(this->pkcs7->d.sign->crl);
	for (int i = 0; i < num; i++) {
		const X509_CRL *oneX509Crl = sk_X509_CRL_value(this->pkcs7->d.sign->crl, i);
		THROW_DECODE_ERROR_IF(oneX509Crl == NULL);
		CertificateRevocationList crl(oneX509Crl);
		ret.push_back(std::move(crl));
	}
	return ret;
}
