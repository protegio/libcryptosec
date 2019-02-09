#include <libcryptosec/pkcs12/Pkcs12.h>

#include <libcryptosec/asymmetric/RSAPublicKey.h>
#include <libcryptosec/asymmetric/DSAPublicKey.h>
#include <libcryptosec/asymmetric/ECDSAPublicKey.h>
#include <libcryptosec/asymmetric/RSAPrivateKey.h>
#include <libcryptosec/asymmetric/DSAPrivateKey.h>
#include <libcryptosec/asymmetric/ECDSAPrivateKey.h>

#include <libcryptosec/exception/EncodeException.h>
#include <libcryptosec/exception/Pkcs12Exception.h>
#include <libcryptosec/exception/AsymmetricKeyException.h>

Pkcs12::Pkcs12(PKCS12* p12)
{
	this->privKey = NULL;
	this->cert = NULL;
	this->pkcs12 = p12;
}

Pkcs12::~Pkcs12()
{
	if(this->privKey != NULL)
	{
		delete this->privKey;
	}
	
	if(this->cert != NULL)
	{
		delete this->cert;
	}
	
	for(unsigned int i = 0 ; i < this->ca.size() ; i++)
	{
		delete ca.at(i);
	}
	
	PKCS12_free(this->pkcs12);
}

ByteArray Pkcs12::getDerEncoded() const
{
	ENCODE_DER_AND_RETURN(this->pkcs12, i2d_PKCS12_bio);
}

PrivateKey* Pkcs12::getPrivKey(std::string password)
{
	PrivateKey* ret = NULL;
	
	if(this->privKey == NULL)
	{
		this->parse(password);
	}
	
	switch (this->privKey->getAlgorithm())
	{
		case AsymmetricKey::RSA:
			ret = new RSAPrivateKey(this->privKey->getEvpPkey());
			break;
			                         
		case AsymmetricKey::DSA:
			ret = new DSAPrivateKey(this->privKey->getEvpPkey());
			break;

		case AsymmetricKey::EC:
			ret = new ECDSAPrivateKey(this->privKey->getEvpPkey());
			break;
	}
	
	if (ret == NULL)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "Pkcs12::getPrivKey");
	}
	
	return ret;
}

Certificate* Pkcs12::getCertificate(std::string password)
{
	if(this->privKey == NULL)
	{
		this->parse(password);
	}
	
	return new Certificate(this->cert->getX509());
}

std::vector<Certificate*> Pkcs12::getAdditionalCertificates(std::string password)
{
	std::vector<Certificate*> ret;
	
	if(this->privKey == NULL)
	{
		this->parse(password);
	}
		
	for(unsigned int i = 0 ; i < this->ca.size() ; i++)
	{
		ret.push_back(new Certificate(*this->ca.at(i)));
	}
	
	return ret;
}

void Pkcs12::parse(std::string password)
{
	EVP_PKEY* pkey = NULL;
	X509* cert = NULL;
	STACK_OF(X509)* ca = NULL;
	unsigned long opensslError = 0;
	const X509* tmp = NULL;
	
	//Limpa fila de erros e carrega tabelas
	ERR_clear_error();	
	//OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	
	if(!PKCS12_parse(this->pkcs12, password.c_str(), &pkey, &cert, &ca))
	{
		opensslError = ERR_get_error();
		
		switch(ERR_GET_REASON(opensslError))
		{
			case PKCS12_R_MAC_VERIFY_FAILURE :
				throw Pkcs12Exception(Pkcs12Exception::PARSE_ERROR, "Pkcs12::parse");
				break;
				
			case PKCS12_R_PARSE_ERROR :
				throw Pkcs12Exception(Pkcs12Exception::MAC_VERIFY_FAILURE, "Pkcs12::parse");
				break;
		}
	}
	
	this->privKey = new PrivateKey((const EVP_PKEY*) pkey);
	this->cert = new Certificate((const X509*) cert);
			
	for(int i = 0 ; i < sk_X509_num(ca) ; i ++)
	{
		tmp = sk_X509_value(ca, i);
		this->ca.push_back(new Certificate(tmp));
	}
	
	EVP_PKEY_free(pkey); // FREE: check
	X509_free(cert); // FREE: check
	sk_X509_pop_free(ca, X509_free); // FREE: check
}
