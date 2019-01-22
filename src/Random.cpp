#include <libcryptosec/Random.h>

#include <libcryptosec/exception/RandomException.h>

#include <openssl/rand.h>

ByteArray* Random::bytes(int nbytes)
{
	int rc;
	ByteArray* ret = NULL;

	ret = new ByteArray(nbytes);
	rc = RAND_bytes(ret->getDataPointer(), nbytes);

	if (rc == -1) {
		throw RandomException(RandomException::NO_IMPLEMENTED_FUNCTION, "Random::bytes");
	} else if (rc == 0)	{
		throw RandomException(RandomException::NO_DATA_SEEDED, "Random::bytes");
	}

	return ret;
}

void Random::seedData(const ByteArray &data)
{
	RAND_seed(data.getConstDataPointer(), data.getSize());
}

void Random::seedFile(const std::string &filename, int nbytes)
{
	int rc;
	rc = RAND_load_file(filename.c_str(), nbytes);
	if (!rc) {
		throw RandomException(RandomException::INTERNAL_ERROR, "Random::seedFile");
	}
}

void Random::cleanSeed()
{
	RAND_cleanup();
}

bool Random::status()
{
	return (RAND_status() ? true : false);
}
