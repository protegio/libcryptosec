#include <libcryptosec/asymmetric/ECDSAPublicKey.h>

#include <libcryptosec/asymmetric/AsymmetricKey.h>
#include <libcryptosec/exception/AsymmetricKeyException.h>

ECDSAPublicKey::ECDSAPublicKey(const EVP_PKEY* evpPkey) : PublicKey(evpPkey)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::EC) {
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "ECDSAPublicKey::ECDSAPublicKey");
	}
}

ECDSAPublicKey::ECDSAPublicKey(const ByteArray& derEncoded) : PublicKey(derEncoded)
{
	AsymmetricKey::Algorithm algorithm;
	algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::EC) {
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "ECDSAPublicKey::ECDSAPublicKey");
	}
}

ECDSAPublicKey::ECDSAPublicKey(const std::string& pemEncoded) : PublicKey(pemEncoded)
{
	AsymmetricKey::Algorithm algorithm;
	algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::EC) {
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "ECDSAPublicKey::ECDSAPublicKey");
	}
}

ECDSAPublicKey::~ECDSAPublicKey()
{
}