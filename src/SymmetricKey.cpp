#include <libcryptosec/SymmetricKey.h>
#include <libcryptosec/ByteArray.h>
#include <libcryptosec/Random.h>

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

SymmetricKey::SymmetricKey(const ByteArray &keyData, SymmetricKey::Algorithm algorithm)
{
	this->keyData = new ByteArray(keyData);
	this->algorithm = algorithm;
}

SymmetricKey::SymmetricKey(const SymmetricKey &symmetricKey)
{
	this->keyData = new ByteArray(*(symmetricKey.getEncoded()));
	this->algorithm = symmetricKey.getAlgorithm();
}

SymmetricKey::~SymmetricKey()
{
	this->keyData->burn();
	delete this->keyData;
}

const ByteArray* SymmetricKey::getEncoded() const
{
	return this->keyData;
}

SymmetricKey::Algorithm SymmetricKey::getAlgorithm() const
{
	return this->algorithm;
}

int SymmetricKey::getSize()
{
	return this->keyData->getSize();
}

SymmetricKey& SymmetricKey::operator =(const SymmetricKey& value)
{
	if(this == &value)
		return *this;

	this->keyData->burn();
	delete this->keyData;

	this->keyData = new ByteArray(*(value.keyData));
    this->algorithm = value.getAlgorithm();
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
}

unsigned int SymmetricKey::getAlgorithmIvSize(SymmetricKey::Algorithm algorithm) {
	switch (algorithm)
	{
		case SymmetricKey::AES_128:
		case SymmetricKey::AES_192:
		case SymmetricKey::AES_256:
			return 16;
	}
}
