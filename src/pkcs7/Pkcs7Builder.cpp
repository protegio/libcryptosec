#include <libcryptosec/pkcs7/Pkcs7Builder.h>

#include <libcryptosec/exception/EncodeException.h>
#include <libcryptosec/exception/Pkcs7Exception.h>
#include <libcryptosec/exception/InvalidStateException.h>
#include <libcryptosec/exception/OperationException.h>
#include <libcryptosec/Macros.h>

Pkcs7Builder::Pkcs7Builder() :
	pkcs7(PKCS7_new()), p7bio(NULL), state(Pkcs7Builder::NO_INIT)
{
	THROW_OPERATION_ERROR_IF(this->pkcs7 == NULL);
}

Pkcs7Builder::~Pkcs7Builder()
{
	if (this->p7bio != NULL) {
		BIO_free(this->p7bio);
		this->p7bio = NULL;
	}

	if (this->pkcs7 != NULL) {
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
	}
}

void Pkcs7Builder::update(const std::string& data)
{
	this->update((const unsigned char*) data.c_str(), data.size() + 1);
}

void Pkcs7Builder::update(const ByteArray& data)
{
	this->update(data.getConstDataPointer(), data.getSize());
}

void Pkcs7Builder::update(const unsigned char* data, unsigned int size)
{
	THROW_OPERATION_ERROR_IF(this->state != Pkcs7Builder::INIT && this->state != Pkcs7Builder::UPDATE);

	if (this->state == Pkcs7Builder::INIT) {
		this->p7bio = PKCS7_dataInit(this->pkcs7, NULL);
		THROW_OPERATION_ERROR_AND_FREE_IF(this->p7bio == NULL,
				this->reset();
		);
	}

	int rc = BIO_write(this->p7bio, data, size);
	THROW_OPERATION_ERROR_AND_FREE_IF(rc == 0,
			this->reset();
	);

	this->state = Pkcs7Builder::UPDATE;
}

void Pkcs7Builder::doFinal(std::istream *in, std::ostream *out)
{
	char *data = NULL;
	int size, rc;
	int maxSize = 1024;

	// TODO: porque não funciona com update?
	THROW_OPERATION_ERROR_IF(this->state == Pkcs7Builder::INIT);

	ByteArray buf(maxSize);
	while ((size = in->readsome((char *) buf.getDataPointer(), maxSize)) > 0) {
		buf.setSize(size);
		this->update(buf);
	}

	THROW_OPERATION_ERROR_AND_FREE_IF(this->state != Pkcs7Builder::UPDATE,
			this->reset();
	);

	rc = BIO_flush(this->p7bio);
	THROW_OPERATION_ERROR_AND_FREE_IF(rc == 0 || rc == -1,
			this->reset();
	);

	rc = PKCS7_dataFinal(this->pkcs7, this->p7bio);
	THROW_OPERATION_ERROR_AND_FREE_IF(rc == 0,
			this->reset();
	);

	BIO *buffer = BIO_new(BIO_s_mem());
	THROW_OPERATION_ERROR_AND_FREE_IF(buffer == NULL,
			this->reset();
	);

	int wrote = PEM_write_bio_PKCS7(buffer, this->pkcs7);
	THROW_OPERATION_ERROR_AND_FREE_IF(wrote == 0,
			BIO_free(buffer);
			this->reset();
	);

	int ndata = BIO_get_mem_data(buffer, &data);
	THROW_OPERATION_ERROR_AND_FREE_IF(ndata <= 0,
			BIO_free(buffer);
			this->reset();
	);

	out->write(data, ndata);

	this->reset();
}

void Pkcs7Builder::reset()
{
	this->state = Pkcs7Builder::NO_INIT;

	if (this->p7bio != NULL) {
		BIO_free(this->p7bio);
		this->p7bio = NULL;
	}

	if (this->pkcs7 != NULL) {
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
		this->pkcs7 = PKCS7_new();
		THROW_OPERATION_ERROR_IF(this->pkcs7 == NULL);
	}
}
