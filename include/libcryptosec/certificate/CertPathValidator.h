#ifndef CERTPATHVALIDATOR_H_
#define CERTPATHVALIDATOR_H_

#include <libcryptosec/certificate/CertPathValidatorResult.h>
#include <libcryptosec/certificate/Certificate.h>
#include <libcryptosec/certificate/CertificateRevocationList.h>
#include <libcryptosec/certificate/ValidationFlags.h>
#include <libcryptosec/DateTime.h>

#include <vector>
#include <time.h>

/**
 * @ingroup Util
 */

/**
 * @brief Valida certificados X509.
  */
class CertPathValidator
{
public:	
	
	/**
	 * Construtor.
	 * @param untrusted certificado a ser validado.
	 * @param untrustedChain vetor contendo os certificados do caminho de certificação. 
	 * @param trustedChain vetor de certificados confiáveis.
	 * @param when momento do tempo para se considerar a validade dos certificados.
	 * @param crls vetor de LCRs.
	 * @param flags vetor de flags para validação.
	 * @param @result ponteiro para objeto de diagnostico de validação em caso de erro.
	 * */
	CertPathValidator(
			const Certificate& untrusted,
			const std::vector<Certificate>& untrustedChain,
			const std::vector<Certificate>& trustedChain,
			const std::vector<CertificateRevocationList>& crls,
			const DateTime& when,
			const std::vector<ValidationFlags>& flags);
	
	/*
	 * Destrutor padrão.
	 * */			
	virtual ~CertPathValidator();
	
	/*
	 * Define momento do tempo para se considerar a validade dos certificados.
	 * @param when objeto DateTime;
	 * */
	void setTime(const DateTime& when);
	
	/*
	 * Define o certificado a ser validado.
	 * @param cert referência a um objeto Certificate.
	 * */
	void setUntrusted(const Certificate& cert);
	
	/*
	 * Define caminho de certificação
	 * @param certs referência a um vetor de Certificados.
	 * */
	void setUnstrustedChain(const vector<Certificate>& certs);
	
	/*
	 * Define certificados confiáveis.
	 * @param certs referência a um vetor de Certificados.
	 * */
	void setTrustedChain(const vector<Certificate>& certs);
	
	/*
	 * Define LCRs
	 * Caso use-se a flag CRL_CHECK, deve-se definir a LCR referente ao certificado a ser validado. Já a flag CRL_CHECK_ALL exige que sejam definidas as LCRs de cada certificado do caminho de certificação, incluindo os certificados confiáveis.
	 * @param crls referência a um vetor de CertificateRevocationList.
	 * */
	void setCrls(const vector<CertificateRevocationList>& crls);

	/*
	 * Define flags de validação
	 * @param flag item da enum ValidationFlags.
	 * */
	void setVerificationFlags(ValidationFlags flag);
	
	/*
	 * Define objeto de diagnóstico de validação.
	 * @param result ponteiro de ponteiro para objeto CertPathValidatorResult.
	 * */
	//void setResult(CertPathValidatorResult** result);
	
	/*
	 * Realiza validação de certificado.
	 * @return true caso o certificado seja válido. Caso o certificado seja inválido, false é retornado e o objeto CertPathValidatorResult é instanciado.
	 * */
	bool verify();
	
	/*
	 * Retorna se há avisos
	 * @return true se há avisos, false caso contrário.
	 * */
	bool getWarningsStatus() const;
	
	/*
	 * Retorna informações sobre a execução da validação.
	 * @return vetor de objetos CertPathValidatorResult;
	 * */
	vector<CertPathValidatorResult> getResults() const;
	
	/*
	 * Função callback de tratamento de erro de validação de assinaturas
	 * @param ok resultado da verificação
	 * @param ctx contexto de certificado
	 * @return 1
	 */
	static int callback(int ok, X509_STORE_CTX *ctx);
	
protected:
	
	/*
	 * Certificado a ser validado.
	 * */
	Certificate untrusted;

	/*
	 * Caminho de certificação.
	 * É opcional incluir neste vetor o certificado a ser verificado e o a AC Raiz.
	 * */
	std::vector<Certificate> untrustedChain;
	
	/*
	 * Certificados confiáveis
	 * */
	std::vector<Certificate> trustedChain;
	
	/*
	 * LCRs para verificar revogação
	 * Deve conter a LCR referente unstrusted se a opção CRL_CHECK é habilitada. 
	 * Se CRL_CHECK_ALL está habilitada, crls deve conter as LCRs referentes a cada certificado da cadeia de certificação.s
	 * */
	std::vector<CertificateRevocationList> crls;
	
	/*
	 * Momento para se considerar a validade dos certificados.
	 * */
	DateTime when;
		
	/*
	 * Opções de validação.
	 * */
	std::vector<ValidationFlags> flags;

	/*
	 * Informações sobre o o resultado da validação.
	 * Esta var estática é utilizada para obter os dados na funcao de callback em C.
	 * Verificar problemas de concorrência com esta variável no caso de multi-threading.
	 * */
	static std::vector<CertPathValidatorResult> results;

};

#endif /*CERTPATHVALIDATOR_H_*/
