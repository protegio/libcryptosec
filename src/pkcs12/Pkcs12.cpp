#include <libcryptosec/pkcs12/Pkcs12.h>

#include <libcryptosec/RSAPublicKey.h>
#include <libcryptosec/DSAPublicKey.h>
#include <libcryptosec/ECDSAPublicKey.h>
#include <libcryptosec/RSAPrivateKey.h>
#include <libcryptosec/DSAPrivateKey.h>
#include <libcryptosec/ECDSAPrivateKey.h>

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
	BIO *buffer;
	int ndata, wrote;
	ByteArray ret;
	unsigned char *data;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "Pkcs12::getDerEncoded");
	}
	
	wrote = i2d_PKCS12_bio(buffer, this->pkcs12);
	if (!wrote)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_ENCODE, "Pkcs12::getDerEncoded");
	}
	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "Pkcs12::getDerEncoded");
	}
	ret = ByteArray(data, ndata);
	BIO_free(buffer);
	return ret;
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