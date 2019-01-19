#include <libcryptosec/RSAPublicKey.h>

RSAPublicKey::RSAPublicKey(EVP_PKEY *key) : PublicKey(key)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::RSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "RSAPublicKey::RSAPublicKey");
	}
}

RSAPublicKey::RSAPublicKey(ByteArray &derEncoded) : PublicKey(derEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::RSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "RSAPublicKey::RSAPublicKey");
	}
}

RSAPublicKey::RSAPublicKey(std::string &pemEncoded)	 : PublicKey(pemEncoded)
{
	AsymmetricKey::Algorithm algorithm;
	algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::RSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "RSAPublicKey::RSAPublicKey");
	}
}

RSAPublicKey::~RSAPublicKey()
{
}
