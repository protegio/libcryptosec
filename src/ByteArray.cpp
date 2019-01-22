#include <libcryptosec/ByteArray.h>
#include <libcryptosec/exception/ByteArrayException.h>

#include <openssl/rand.h>

ByteArray::ByteArray()
{
    this->m_data = NULL;
    this->size = 0;
    this->originalSize = 0;
}

ByteArray::ByteArray(unsigned int size)
{
    this->size = size;
    this->originalSize = size;
    this->m_data = new unsigned char[size + 1];
    memset(this->m_data, 0, this->size + 1);
}

ByteArray::ByteArray(const unsigned char* data, unsigned int size)
{
    this->size = size;
    this->originalSize = size;
    this->m_data = new unsigned char[size + 1];
    memcpy(this->m_data, data, size);
    this->m_data[size] = '\0';
}

ByteArray::ByteArray(std::ostringstream *buffer)
{
	std::string data = buffer->str();
	this->size = data.size() + 1;
	this->originalSize = this->size;
    this->m_data = new unsigned char[size + 1];
    memcpy(this->m_data, (const unsigned char *) data.c_str(), this->size);
    this->m_data[size] = '\0';
}

ByteArray::ByteArray(const std::string& data)
{
	this->size = data.size() + 1;
	this->originalSize = this->size;
    this->m_data = new unsigned char[this->size + 1];
    memcpy(this->m_data, data.c_str(), this->size);
    this->m_data[this->size] = '\0';
}

ByteArray::ByteArray(const char *data)
{
	this->size = strlen(data) + 1;
	this->originalSize = this->size;
    this->m_data = new unsigned char[this->size + 1];
    memcpy(this->m_data, data, size);
    this->m_data[this->size] = '\0';
}

ByteArray::ByteArray(const ByteArray& value)
{
    this->size = value.size;
    this->originalSize = value.originalSize;
    this->m_data = new unsigned char[this->originalSize + 1];
    memcpy(this->m_data, value.m_data, this->originalSize);
    this->m_data[this->originalSize] = '\0';
}

ByteArray::~ByteArray()
{
    delete[] this->m_data;
}

ByteArray& ByteArray::operator =(const ByteArray& value)
{
    if(this->m_data) {
    	delete[] this->m_data;
    }

    this->size = value.size;
    this->originalSize = value.originalSize;
    this->m_data = new unsigned char[this->originalSize + 1];
    memcpy(this->m_data, value.m_data, this->originalSize);
    this->m_data[this->originalSize] = '\0';

    return (*this);
}

bool operator ==(const ByteArray& left, const ByteArray& right)
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

unsigned char& ByteArray::operator [](unsigned int pos)
{
	if(pos < 0 || pos >= this->size) {
		throw std::out_of_range("");
	}

    return this->m_data[pos];
}

unsigned char ByteArray::at(unsigned int pos) const
{
	if(pos < 0 || pos >= this->size) {
		throw std::out_of_range("");
	}

	return this->m_data[pos];
}

void ByteArray::copyFrom(unsigned char* data, unsigned int size)
{
	this->setSize(size);
	memcpy(this->m_data, data, size);
}

void ByteArray::copyTo(ByteArray& to, unsigned int toOffset, unsigned int fromOffset, unsigned int fromSize) const
{
	if (this->size < (fromOffset + fromSize) || to.size < toOffset || to.size < fromSize)
		throw std::out_of_range("");

    for (unsigned int top = fromOffset + fromSize; toOffset < top; toOffset++, fromOffset++) {
        to.m_data[toOffset] = this->m_data[fromOffset];
    }
}

void ByteArray::setDataPointer(unsigned char* d, unsigned int size)
{
	if(this->m_data) {
		delete[] this->m_data;
	}

	this->size = size;
	this->originalSize = size;
	this->m_data = d;
}

const unsigned char* ByteArray::getConstDataPointer() const {
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
		this->m_data = new_m_data;
		this->size = size;
		this->originalSize = size;
	}
}

std::string ByteArray::toString() const
{
	return (char *) this->m_data;
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

std::istringstream* ByteArray::toInputStringStream() const
{
	std::string data((const char *) this->m_data, this->size + 1);
	std::istringstream *stream = new std::istringstream(data);
	return stream;
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
