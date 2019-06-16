#include <libcryptosec/ByteArray.h>
#include <libcryptosec/exception/ByteArrayException.h>
#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/NullPointerException.h>

#include <openssl/rand.h>

#include <string.h>
#include <stdio.h>

ByteArray::ByteArray() :
		ByteArray(0)
{
}

ByteArray::ByteArray(uint32_t size) :
		size(size),
		originalSize(size)
{
	THROW_OVERFLOW_IF(size == UINT32_MAX);
	this->m_data = new unsigned char[size + 1];
	// TODO: precisamos desse memset?
	// Ele impede que dados sensíveis vazem no caso de um memory leak
	// Mas torna bem lenta a alocação do byte array
    memset(this->m_data, 0, this->size + 1);
    this->m_data[size] = '\0';
}

ByteArray::ByteArray(const uint8_t* data, uint32_t size) :
		size(size),
		originalSize(size)
{
	THROW_OVERFLOW_IF(size == UINT32_MAX);
	this->m_data = new unsigned char[size + 1];
    memcpy(this->m_data, data, size);
    this->m_data[size] = '\0';
}

ByteArray::ByteArray(const std::string& data) :
		size(data.size()),
		originalSize(size),
		m_data(new unsigned char[size + 1])
{
    memcpy(this->m_data, data.c_str(), this->size);
    this->m_data[this->size] = '\0';
}

ByteArray::ByteArray(const ByteArray& value) :
		size(value.size),
		originalSize(value.originalSize),
		m_data(new unsigned char[value.originalSize + 1])
{
    memcpy(this->m_data, value.m_data, this->originalSize);
    this->m_data[this->originalSize] = '\0';
}

ByteArray::ByteArray(ByteArray&& value) :
		size(std::move(value.size)),
		originalSize(std::move(value.originalSize)),
		m_data(std::move(value.m_data))
{
	value.size = 0;
	value.originalSize = 0;
	value.m_data = nullptr;
}

ByteArray::~ByteArray()
{
    delete[] this->m_data;
}

ByteArray& ByteArray::operator=(const ByteArray& value)
{
	if (&value == this) {
		return *this;
	}

    if(this->m_data) {
    	delete[] this->m_data;
    }

    this->size = value.size;
    this->originalSize = value.originalSize;
    this->m_data = new unsigned char[this->originalSize + 1];
    memcpy(this->m_data, value.m_data, this->originalSize);
    this->m_data[this->originalSize] = '\0';

    return *this;
}

ByteArray& ByteArray::operator=(ByteArray&& value)
{
	if (&value == this) {
		return *this;
	}

    if(this->m_data) {
    	delete[] this->m_data;
    }

    this->size = value.size;
    this->originalSize = value.originalSize;
    this->m_data = value.m_data;
	value.size = 0;
	value.originalSize = 0;
	value.m_data = nullptr;

    return *this;
}

uint8_t& ByteArray::at(uint32_t pos) const
{
	THROW_OUT_OF_RANGE_IF(pos >= this->size);
	return this->m_data[pos];
}

uint8_t& ByteArray::operator [](unsigned int pos)
{
	return this->at(pos);
}

bool operator==(const ByteArray& left, const ByteArray& right)
{
	// TODO: we should consider using a constant time method
	int cmp_result = 0;

    if(left.size != right.size)
        return false;

    cmp_result = memcmp(left.m_data, right.m_data, left.size);
    
    return (cmp_result ? false : true);
}

bool operator !=(const ByteArray& left, const ByteArray& right)
{
	// TODO: we should consider using a constant time method
	int cmp_result = 0;

    if(left.size != right.size)
        return true;
    
    cmp_result = memcmp(left.m_data, right.m_data, left.size);
    
    return (cmp_result ? true : false);
}

void ByteArray::copy(const ByteArray& from, uint32_t fromOffset, uint32_t toOffset, uint32_t numberOfBytes)
{
	THROW_OVERFLOW_IF(UINT32_MAX-fromOffset < numberOfBytes);
	THROW_OVERFLOW_IF(UINT32_MAX-toOffset < this->size);
	THROW_OUT_OF_RANGE_IF(from.size < (fromOffset + numberOfBytes));

	if(toOffset + numberOfBytes > this->size)
		this->setSize(toOffset + numberOfBytes);

	for (uint32_t top = toOffset + numberOfBytes; toOffset < top; toOffset++, fromOffset++) {
        this->m_data[toOffset] = from.m_data[fromOffset];
    }
}

const uint8_t* ByteArray::getConstDataPointer() const
{
	return this->m_data;
}

unsigned char* ByteArray::getDataPointer()
{
	return this->m_data;
}

unsigned int ByteArray::getSize() const
{
	return this->size;
}

void ByteArray::setSize(unsigned int size)
{
	if (size <= this->originalSize) {
		this->size = size;
	} else {
		unsigned char* new_m_data = new unsigned char[size + 1];
		memcpy(new_m_data, this->m_data, this->originalSize);
		if(this->m_data) {
			delete[] this->m_data;
		}
		this->m_data = new_m_data;
		this->size = size;
		this->originalSize = size;
	}
}

std::string ByteArray::toString() const
{
	return std::string((char *) this->m_data, this->size);
}

std::string ByteArray::toHex() const
{
	std::string data;	
	char *hex_data = new char[this->size * 2 +1];

	unsigned int j = 0;
	for(unsigned int i = 0; i < this->size; i++)
	{
		sprintf(&hex_data[j], "%02X", this->m_data[i]);
		j += 2;
	}

	hex_data[j] = '\0';
	data = hex_data;

	delete[] hex_data;

	return data;
}

std::string ByteArray::toHex(char separator) const
{
	std::stringstream data;	
    char* hex_data = new char[2];
    
    for(unsigned int i = 0; i < this->size; i++)
    {    	
		sprintf(&hex_data[0], "%02X", this->m_data[i]);
		data << hex_data;
		if(i < this->size - 1)
			data << separator;
    }

	delete[] hex_data;

    return data.str();
}

ByteArray& operator xor(const ByteArray& left, const ByteArray& right)
{
	const ByteArray* biggest = 0;
	const ByteArray* smallest = 0;

	if (left.getSize() > right.getSize()) {
		biggest = &left;
		smallest = &right;
	} else {
		biggest = &right;
		smallest = &left;
	}

	ByteArray *xored = new ByteArray(*biggest);
	for (unsigned int i = 0; i < smallest->getSize(); i++) {
		(*xored)[i] = (*xored)[i] xor smallest->at(i);
	}

	return (*xored);
}

void ByteArray::burn(bool useRandomBytes) {
	if (!useRandomBytes) {
		memset(this->m_data, 0, this->originalSize);
	} else {
		if (this->originalSize > INT32_MAX) {
			if (RAND_bytes(this->m_data, INT32_MAX) == 0)
				throw ByteArrayException(ByteArrayException::RANDOM_ERROR, "ByteArray::burn");

			if (RAND_bytes(this->m_data + INT32_MAX, this->originalSize - INT32_MAX) == 0)
				throw ByteArrayException(ByteArrayException::RANDOM_ERROR, "ByteArray::burn");
		} else {
			if(RAND_bytes(this->m_data, (int) this->originalSize) == 0)
				throw ByteArrayException(ByteArrayException::RANDOM_ERROR, "ByteArray::burn");
		}
	}
}

ASN1_OCTET_STRING* ByteArray::getAsn1OctetString() const
{
	ASN1_OCTET_STRING *ret = ASN1_OCTET_STRING_new();
	if (ret == NULL) {
		throw ByteArrayException(/* TODO */);
	}

	int rc = ASN1_OCTET_STRING_set(ret, this->m_data, this->size);
	if (rc == 0) {
		throw ByteArrayException(/* TODO */);
	}
	return ret;
}
