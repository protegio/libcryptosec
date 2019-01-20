#ifndef PKCS12_H_
#define PKCS12_H_

#include <openssl/pkcs12.h>

#include "ByteArray.h"
#include "RSAPublicKey.h"
#include "DSAPublicKey.h"
#include "ECDSAPublicKey.h"
#include "RSAPrivateKey.h"
#include "DSAPrivateKey.h"
#include "ECDSAPrivateKey.h"

#include <libcryptosec/certificate/Certificate.h>
#include <libcryptosec/exception/EncodeException.h>
#include <libcryptosec/exception/Pkcs12Exception.h>

class Pkcs12
{
public:
	Pkcs12(PKCS12* p12);
	virtual ~Pkcs12();
	
	/**
	 * @return o conteudo em codificacao DER do pacote Pkcs12
	 * */
	ByteArray getDerEncoded() const;
	
	/**
	 * Retorna uma copia da chave privada encapsulada pelo objeto Pkcs12
	 * @param password passphrase do pacote Pkcs12
	 * */
	PrivateKey* getPrivKey(std::string password);
	
	/**
	 * Retorna uma copia do certificado encapsulados pelo objeto Pkcs12
	 * @param password passphrase do pacote Pkcs12
	 * */
	Certificate* getCertificate(std::string password);
	
	/**
	 * Retorna uma copia dos certificados adicionais encapsulados pelo objeto Pkcs12
	 * @param password passphrase do pacote Pkcs12
	 * */
	std::vector<Certificate*> getAdditionalCertificates(std::string password);

protected:
	/**
	 * Popula os objetos internos da classe: privKey, cert e ca.
	 * @param password passphrase do pacote Pkcs12
	 * */
	void parse(std::string password);
	
protected:
	PrivateKey* privKey;
	Certificate* cert;
	std::vector<Certificate*> ca;
	PKCS12* pkcs12;
};

#endif /*PKCS12_H_*/
