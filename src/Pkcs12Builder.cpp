#include <libcryptosec/Pkcs12Builder.h>

#include <libcryptosec/exception/Pkcs12Exception.h>

#include <string.h>

Pkcs12Builder::Pkcs12Builder(const PrivateKey& key, const Certificate& cert,
		const std::string& friendlyName) :
		key(key), cert(cert), friendlyName(friendlyName)
{
}

Pkcs12Builder::~Pkcs12Builder()
{
}

void Pkcs12Builder::setKeyAndCertificate(const PrivateKey& key, const Certificate& cert,
		const std::string& friendlyName)
{
	this->key = key;
	this->cert = cert;
	this->friendlyName = friendlyName;
}

void Pkcs12Builder::setAdditionalCerts(const std::vector<Certificate>& certs)
{
	this->certs = certs;
}

void Pkcs12Builder::addAdditionalCert(const Certificate& cert)
{
	this->certs.push_back(cert);
}

void Pkcs12Builder::clearAdditionalCerts()
{
	this->certs.clear();
}

Pkcs12 Pkcs12Builder::doFinal(const std::string& password)
{
	STACK_OF(X509)* ca = NULL;
	char* cpass = NULL;
	char* cname = NULL;	
	
	int nid_key = 0;
	int nid_cert = 0;
	int iter = 0;
	int mac_iter = 0;
	int keytype = 0;

	//verifica se chave privada corresponde a chave publica
	if(!X509_check_private_key(this->cert.getX509(), this->key.getEvpPkey()))
	{
		throw Pkcs12Exception(Pkcs12Exception::KEY_AND_CERT_DO_NOT_MATCH, "Pkcs12Builder::doFinal");
	}
	
	//cria array de char para password
	cpass = new char[password.size() + 1];
	strcpy(cpass, password.c_str());
	
	//cria array de char para friendlyname
	if(friendlyName.compare("") != 0)
	{
		cname = new char[this->friendlyName.size() + 1];
		strcpy(cname, this->friendlyName.c_str());
	}
	
	//cria pilha de certificados
	ca = sk_X509_new_null();
	for(auto cert : this->certs) {
		sk_X509_push(ca, cert.getSslObject());
	}
	
	//cria estruta PKCS12
	Pkcs12 tmp(
		/* CAST: TODO: o argumento evp_pkey não foi verificado */
		/* CAST: PKCS12_create não modifica o certificado. */
		/* CAST: TODO: o argumento ca não foi verificado */
		PKCS12_create(
			cpass, cname, (EVP_PKEY*) this->key.getEvpPkey(),
			(X509*) this->cert.getX509(), ca,
			nid_key, nid_cert,
			iter, mac_iter,
			keytype
		)
	);

	delete[] cpass;
	delete[] cname;
	sk_X509_free(ca);

	return std::move(tmp);
}
