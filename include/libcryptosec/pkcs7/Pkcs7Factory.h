#ifndef PKCS7FACTORY_H_
#define PKCS7FACTORY_H_

#include <libcryptosec/pkcs7/Pkcs7.h>
#include <libcryptosec/pkcs7/Pkcs7SignedData.h>
#include <libcryptosec/pkcs7/Pkcs7EnvelopedData.h>
#include <libcryptosec/ByteArray.h>

#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/asn1.h>

#include <string>

/**
 * Implementa o padrão Factory para a criação de pacotes PKCS7
 * @ingroup PKCS7
 **/

class Pkcs7Factory
{
	
public:
	
	/**
	 * Método estático que carrega um pacote PKCS7 a partir de seu equivalente codificado em DER.
	 * @param derEncoded pacote PKCS7 no formato binário DER.
	 * @return o pacote PKCS7 correspondente ao lido a partir de sua codificação em DER.
	 * @throw Pkcs7Exception se ocorrer algum probelma na geração do pacote PKCS7.
	 * @throw EncodeException se ocorrer algum problema na decodificação do pacote DER.
	 **/
	static Pkcs7* fromDerEncoded(ByteArray &derEncoded);
	
	/**
	 * Método estático que carrega um pacote PKCS7 a partir de seu equivalente codificado em PEM.
	 * @param pemEncoded pacote PKCS7 no formato texto PEM.
	 * @return o pacote PKCS7 correspondente ao lido a partir de sua codificação em PEM.
	 * @throw Pkcs7Exception se ocorrer algum probelma na geração do pacote PKCS7.
	 * @throw EncodeException se ocorrer algum problema na decodificação do pacote PEM.
	 **/		
	static Pkcs7* fromPemEncoded(std::string &pemEncoded);
			
};

#endif /*PKCS7FACTORY_H_*/
