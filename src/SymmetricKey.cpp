#include <libcryptosec/SymmetricKey.h>
#include <libcryptosec/ByteArray.h>
#include <libcryptosec/Random.h>
#include <libcryptosec/exception/SymmetricKeyException.h>

INITIALIZE_ENUM( SymmetricKey::Algorithm, 3,
	AES_128,
	AES_192,
	AES_256
);

SymmetricKey::SymmetricKey(SymmetricKey::Algorithm algorithm)
{
	unsigned int size = 0;

	switch (algorithm) {
	case AES_128:
		size = 128;
		break;
	case AES_192:
		size = 192;
		break;
	case AES_256:
		size = 256;
		break;
	}

	this->algorithm = algorithm;
	this->keyData = Random::bytes(size);
}

SymmetricKey::SymmetricKey(const ByteArray &keyData, SymmetricKey::Algorithm algorithm) :
		keyData(keyData), algorithm(algorithm)
{
}

SymmetricKey::~SymmetricKey()
{
	this->keyData.burn();
}

const ByteArray& SymmetricKey::getEncoded() const
{
	return this->keyData;
}

SymmetricKey::Algorithm SymmetricKey::getAlgorithm() const
{
	return this->algorithm;
}

unsigned int SymmetricKey::getSize()
{
	return this->keyData.getSize();
}

unsigned int SymmetricKey::getAlgorithmIvSize() {
	return SymmetricKey::getAlgorithmIvSize(this->algorithm);
}

SymmetricKey& SymmetricKey::operator=(const SymmetricKey& value)
{
	if(this == &value) {
		return *this;
	}

	this->keyData.burn();
	this->keyData = value.keyData;
    this->algorithm = value.algorithm;

    return *this;
}

SymmetricKey& SymmetricKey::operator=(SymmetricKey&& value)
{
	if(this == &value) {
		return *this;
	}

	this->keyData.burn();
	this->keyData = std::move(value.keyData);
    this->algorithm = std::move(value.algorithm);

    return *this;
}

std::string SymmetricKey::getAlgorithmName(SymmetricKey::Algorithm algorithm)
{
	std::string ret;
	switch (algorithm)
	{
		case SymmetricKey::AES_128:
			ret = "aes-128";
			break;
		case SymmetricKey::AES_192:
			ret = "aes-192";
			break;
		case SymmetricKey::AES_256:
			ret = "aes-256";
			break;
	}
	return ret;
}

unsigned int SymmetricKey::getAlgorithmBlockSize(SymmetricKey::Algorithm algorithm) {
	switch (algorithm)
	{
		case SymmetricKey::AES_128:
		case SymmetricKey::AES_192:
		case SymmetricKey::AES_256:
			return 16;
	}
	throw SymmetricKeyException(SymmetricKeyException::INVALID_ALGORITHM, "SymmetricKey::getAlgorithmBlockSize");
}

unsigned int SymmetricKey::getAlgorithmIvSize(SymmetricKey::Algorithm algorithm) {
	switch (algorithm)
	{
		case SymmetricKey::AES_128:
		case SymmetricKey::AES_192:
		case SymmetricKey::AES_256:
			return 16;
	}
	throw SymmetricKeyException(SymmetricKeyException::INVALID_ALGORITHM, "SymmetricKey::getAlgorithmIvSize");
}
