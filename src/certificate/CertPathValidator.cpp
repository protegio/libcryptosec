#include <libcryptosec/certificate/CertPathValidator.h>

#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/OperationException.h>

std::vector<CertPathValidatorResult> CertPathValidator::results;

CertPathValidator::CertPathValidator(
		const Certificate& untrusted,
		const std::vector<Certificate>& untrustedChain,
		const std::vector<Certificate>& trustedChain,
		const std::vector<CertificateRevocationList>& crls,
		const DateTime& when,
		const std::vector<ValidationFlags>& flags) :
		untrusted(untrusted),
		untrustedChain(untrustedChain),
		trustedChain(trustedChain),
		crls(crls),
		when(when),
		flags(flags)
{
}

CertPathValidator::~CertPathValidator()
{
}

void CertPathValidator::setTime(const DateTime& when)
{
	this->when = when;
}

void CertPathValidator::setUntrusted(const Certificate& cert)
{
	this->untrusted = cert;
}

void CertPathValidator::setUnstrustedChain(const vector<Certificate>& certs)
{
	this->untrustedChain = certs;
}

void CertPathValidator::setTrustedChain(const vector<Certificate>& certs)
{
	this->trustedChain = certs;
}

void CertPathValidator::setCrls(const vector<CertificateRevocationList>& crls)
{
	this->crls = crls;
}

void CertPathValidator::setVerificationFlags(ValidationFlags flag)
{
	this->flags.push_back(flag);
}

bool CertPathValidator::verify()
{
	bool ret;
	int rc = 0;

	/** TODO CHECK if needed. Move to init? */
	ERR_load_crypto_strings();

	/*instancia store de certificados
	 * ignorou-se a possibilidade de falta de memoria
	 */
	X509_STORE *store = X509_STORE_new();
	THROW_OPERATION_ERROR_IF(store == NULL);

	/*instancia contexto
	 * ignorou-se a possibilidade de falta de memoria
	 */
	X509_STORE_CTX *storeCtx = X509_STORE_CTX_new();
	THROW_OPERATION_ERROR_AND_FREE_IF(store == NULL,
			X509_STORE_free(store);
	);
	
	/*instancia pilha de certificados para conter caminho de certificacao
	 * ignorou-se a possibilidade de falta de memoria
	 */
	STACK_OF(X509) *certs = sk_X509_new_null();
	THROW_OPERATION_ERROR_AND_FREE_IF(certs == NULL,
			X509_STORE_free(store);
			X509_STORE_CTX_free(storeCtx);
	);
	
	//popula pilha
	for(auto certificate : this->untrustedChain) {
		X509 *sslCertificate = NULL;

		try{
			sslCertificate = certificate.getSslObject();
		} catch (...) {
			X509_STORE_free(store);
			X509_STORE_CTX_free(storeCtx);
			sk_X509_pop_free(certs, X509_free);
		}

		// TODO: sk_X509_push copy or move?
		rc = sk_X509_push(certs, (X509*) sslCertificate);
		THROW_OPERATION_ERROR_AND_FREE_IF(rc == 0,
				X509_STORE_free(store);
				X509_STORE_CTX_free(storeCtx);
				sk_X509_pop_free(certs, X509_free);
				X509_free(sslCertificate);
		);
	}
	
	//define funcao de callback
	X509_STORE_set_verify_cb_func(store, CertPathValidator::callback);
	// X509_STORE_set_verify_cb_func não retorna erro

	//define certificados confiaveis
	for(auto certificate : this->trustedChain) {
		const X509 *sslCertificate = certificate.getX509();
		// CAST: X509_STORE_add_cert não modifica sslCertificate
		rc = X509_STORE_add_cert(store, (X509*) sslCertificate);
		THROW_OPERATION_ERROR_AND_FREE_IF(rc == 0,
				X509_STORE_free(store);
				X509_STORE_CTX_free(storeCtx);
				sk_X509_pop_free(certs, X509_free);
		);
	}			
	
	//define flags
	for(auto flag : this->flags)
	{
		switch(flag) {
			case CRL_CHECK:
				rc = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
				THROW_OPERATION_ERROR_AND_FREE_IF(rc == 0,
						X509_STORE_free(store);
						X509_STORE_CTX_free(storeCtx);
						sk_X509_pop_free(certs, X509_free);
				);
				break;
			
			case CRL_CHECK_ALL:
				/*precisa por CRL_CHECK tambem, caso contrario o openssl nao verifica CRL*/
				rc = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
				THROW_OPERATION_ERROR_AND_FREE_IF(rc == 0,
						X509_STORE_free(store);
						X509_STORE_CTX_free(storeCtx);
						sk_X509_pop_free(certs, X509_free);
				);

				rc = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK_ALL);
				THROW_OPERATION_ERROR_AND_FREE_IF(rc == 0,
						X509_STORE_free(store);
						X509_STORE_CTX_free(storeCtx);
						sk_X509_pop_free(certs, X509_free);
				);
				break;
		}
	}
	
	/*adiciona crls ao store*/
	for(auto crl : this->crls) {
		const X509_CRL *sslCrl = crl.getX509Crl();
		// CAST: X509_STORE_add_crl não modifica sslCrl
		rc = X509_STORE_add_crl(store, (X509_CRL*) sslCrl);
		THROW_OPERATION_ERROR_AND_FREE_IF(rc == 0,
				X509_STORE_free(store);
				X509_STORE_CTX_free(storeCtx);
				sk_X509_pop_free(certs, X509_free);
		);
	}
	
	/* inicializa contexto
	 * ignorou-se a possibilidade de falta de memoria
	 */
	const X509 *sslUntrusted = this->untrusted.getX509();
	// CAST: X509_STORE_CTX_init não modifica sslUntrusted
	rc = X509_STORE_CTX_init(storeCtx, store, (X509*) sslUntrusted, certs);
	THROW_OPERATION_ERROR_AND_FREE_IF(rc == 0,
			X509_STORE_free(store);
			X509_STORE_CTX_free(storeCtx);
			sk_X509_pop_free(certs, X509_free);
	);
	
	/* define a data para verificar os certificados da cadeia
	* obs: o segundo parametro da funcao 
	* void X509_STORE_CTX_set_time(X509_STORE_CTX *ctx, unsigned long flags, time_t t)
	* nao eh utilizado, segundo verificou-se no arquivo crypto/x509/x509_vfy.c
	*/
	time_t sslWhen = this->when.getDateTime();
	X509_STORE_CTX_set_time(storeCtx, 0 , sslWhen);
	// X509_STORE_CTX_set_time não retorna erro

	/*Garante que não há informações de validações prévias*/
	CertPathValidator::results.clear();
	
	/*verifica certificado*/
	rc = X509_verify_cert(storeCtx);
	if (rc == 1) {
		ret = true;
	} else {
		//this case can be a error 
		ret = false;
	}
	
	/*desaloca estruturas*/
	sk_X509_pop_free(certs, X509_free);
	X509_STORE_free(store);
	X509_STORE_CTX_free(storeCtx);

	return ret;

}

vector<CertPathValidatorResult> CertPathValidator::getResults() const
{
	return CertPathValidator::results;
}

bool CertPathValidator::getWarningsStatus() const
{
	bool ret = false;
	if(CertPathValidator::results.size() > 0) {
		ret = true;
	}
	return ret;
}

int CertPathValidator::callback(int ok, X509_STORE_CTX *ctx)
{
	Certificate *cert = NULL;
	CertPathValidatorResult aResult;
	
	if (ok) {
		return ok;
	}

	int error = X509_STORE_CTX_get_error(ctx);
	int error_depth = X509_STORE_CTX_get_error_depth(ctx);
	const X509* current_cert = X509_STORE_CTX_get_current_cert(ctx);

	if (current_cert) {
		cert = new Certificate(current_cert);
	}

	aResult.setInvalidCertificate(cert);
	delete cert;
	aResult.setDepth(error_depth);
	aResult.setErrorCode(CertPathValidatorResult::long2ErrorCode(error));

	/*
	* O aplicativo apps/verify.c do OpenSSL ignora todos os erros abaixo.
	* Porem discorda-se nos erros X509_V_ERR_CERT_HAS_EXPIRED e X509_V_ERR_INVALID_CA
	* ok = 0 são considerados erros e interrompem a validação
	* ok = 1 são considerados como avisos e não interrompem a validação
	*/
	if (error == X509_V_ERR_CERT_HAS_EXPIRED) ok = 0;
	if (error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) ok = 1;
	if (error == X509_V_ERR_INVALID_CA) ok = 0;
	if (error == X509_V_ERR_INVALID_NON_CA) ok = 1;
	if (error == X509_V_ERR_PATH_LENGTH_EXCEEDED) ok = 1;
	if (error == X509_V_ERR_INVALID_PURPOSE) ok = 1;
	if (error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) ok = 1;
	if (error == X509_V_ERR_CRL_HAS_EXPIRED) ok = 1;
	if (error == X509_V_ERR_CRL_NOT_YET_VALID) ok = 1;
	if (error == X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION) ok = 1;

	/*
	 * Na ocorrência de erro, os avisos (warnings) antigos são descartados
	 * */
	if(!ok) {
		CertPathValidator::results.clear();
	}

	CertPathValidator::results.push_back(aResult);
		
	/*
	 * TODO incluir informacoes de erro de politicas na classe CertPathValidatorResult
	 *	if (ctx->error == X509_V_ERR_NO_EXPLICIT_POLICY)
	 *		policies_print(NULL, ctx);
	 */
	return ok;
}
