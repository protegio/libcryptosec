#include <libcryptosec/SymmetricKeyGenerator.h>

SymmetricKey* SymmetricKeyGenerator::generateKey(SymmetricKey::Algorithm alg)
{
	ByteArray key;
	key = Random::bytes(EVP_MAX_KEY_LENGTH);
	return new SymmetricKey(key, alg);
}

SymmetricKey* SymmetricKeyGenerator::generateKey(SymmetricKey::Algorithm alg, int size)
{
	ByteArray key;
	key = Random::bytes(size);
	return new SymmetricKey(key, alg);
}
