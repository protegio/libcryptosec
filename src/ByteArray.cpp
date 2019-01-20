#include <libcryptosec/ByteArray.h>

ByteArray::ByteArray()
{
    this->m_data = NULL;
    this->length = 0;
    this->originalLength = 0;
}

ByteArray::ByteArray(unsigned int length)
{
    this->length = length;
    this->originalLength = length;
    this->m_data = new unsigned char[length + 1];
    memset(this->m_data, 0, this->length + 1);
}

ByteArray::ByteArray(const unsigned char* data, unsigned int length)
{
    this->length = length;
    this->originalLength = length;
    this->m_data = new unsigned char[length + 1];
    memcpy(this->m_data, data, length);
    this->m_data[length] = '\0';
}

ByteArray::ByteArray(std::ostringstream *buffer)
{
	std::string data = buffer->str();
	this->length = data.size() + 1;
	this->originalLength = this->length;
    this->m_data = new unsigned char[length+1];
    memcpy(this->m_data, (const unsigned char *) data.c_str(), this->length);
    this->m_data[length] = '\0';
}

ByteArray::ByteArray(const std::string& data)
{
	this->length = data.size() + 1;
	this->originalLength = this->length;
    this->m_data = new unsigned char[this->length + 1];
    memcpy(this->m_data, data.c_str(), this->length);
    this->m_data[this->length] = '\0';
}

ByteArray::ByteArray(const char *data)
{
	this->length = strlen(data) + 1;
	this->originalLength = this->length;
    this->m_data = new unsigned char[this->length + 1];
    memcpy(this->m_data, data, length);
    this->m_data[this->length] = '\0';
}

ByteArray::ByteArray(const ByteArray& value)
{
    this->length = value.length;
    this->originalLength = value.originalLength;
    this->m_data = new unsigned char[this->originalLength + 1];
    memcpy(this->m_data, value.m_data, this->originalLength);
    this->m_data[this->originalLength] = '\0';
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

    this->length = value.length;
    this->originalLength = value.originalLength;
    this->m_data = new unsigned char[this->originalLength + 1];
    memcpy(this->m_data, value.m_data, this->originalLength);
    this->m_data[this->originalLength] = '\0';

    return (*this);
}

bool operator ==(const ByteArray& left, const ByteArray& right)
{
	// TODO: we should consider using a constant time method
	int cmp_result = 0;

    if(left.length != right.length)
        return false;

    cmp_result = memcmp(left.m_data, right.m_data, left.length);
    
    return (cmp_result ? false : true);
}

bool operator !=(const ByteArray& left, const ByteArray& right)
{
	// TODO: we should consider using a constant time method
	int cmp_result = 0;

    if(left.length != right.length)
        return true;
    
    cmp_result = memcmp(left.m_data, right.m_data, left.length);
    
    return (cmp_result ? true : false);
}

unsigned char& ByteArray::operator [](unsigned int pos)
{
	if(pos < 0 || pos >= this->length) {
		throw std::out_of_range("");
	}

    return this->m_data[pos];
}

char ByteArray::at(unsigned int pos) const
{
	if(pos < 0 || pos >= this->length) {
		throw std::out_of_range("");
	}

	return this->m_data[pos];
}

void ByteArray::copyFrom(unsigned char* d, unsigned int length)
{
	if(this->m_data) {
    	delete this->m_data;
	}

	this->length = length;
	this->m_data   = new unsigned char[this->length];
	memcpy(this->m_data, d, length);
}

// TODO: this looks wrong
void ByteArray::copyFrom(int offset, int length, ByteArray& data, int offset2)
{
    for (int top = offset + length; offset < top; offset++, offset2++) {
        data.m_data[offset2] = this->m_data[offset];
    }
}

void ByteArray::setDataPointer(unsigned char* d, unsigned int length)
{
	if(this->m_data)
		delete this->m_data;

	this->length = length;
	this->m_data = d;
}

const unsigned char* ByteArray::getConstDataPointer() const {
	return this->m_data;
}

unsigned char* ByteArray::getDataPointer()
{
	return this->m_data;
}

unsigned int ByteArray::size() const
{
	return this->length;
}

void ByteArray::setSize(unsigned int size)
{

	if (size <= this->originalLength) {
		this->length = size;
	} else {
		unsigned char* new_m_data = new unsigned char[size + 1];
		memcpy(new_m_data, this->m_data, this->originalLength);
		this->m_data = new_m_data;
		this->length = size;
		this->originalLength = size;
	}
}

std::string ByteArray::toString() const
{
	return (char *) this->m_data;
}

std::string ByteArray::toHex() const
{
	std::string data;	
	char *hex_data = new char[this->length * 2 +1];

	unsigned int j = 0;
	for(unsigned int i = 0; i < this->length; i++)
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
    
    for(unsigned int i = 0; i < this->length; i++)
    {    	
		sprintf(&hex_data[0], "%02X", this->m_data[i]);
		data << hex_data;
		if(i < this->length-1)
			data << separator;
    }

	delete[] hex_data;

    return data.str();
}

std::istringstream* ByteArray::toInputStringStream()
{
	std::string data((const char *) this->m_data, this->length + 1);
	std::istringstream *stream = new std::istringstream(data);
	return stream;
}

ByteArray& operator xor(const ByteArray& left, const ByteArray& right)
{
	const ByteArray* biggest = 0;
	const ByteArray* smallest = 0;

	if (left.size() > right.size()) {
		biggest = &left;
		smallest = &right;
	} else {
		biggest = &right;
		smallest = &left;
	}

	ByteArray *xored = new ByteArray(*biggest);
	for (unsigned int i = 0; i < smallest->size(); i++) {
		(*xored)[i] = (*xored)[i] xor smallest->at(i);
	}

	return (*xored);
}

ByteArray ByteArray::xOr(std::vector<ByteArray> &array)
{
	if (array.size() < 1)
		return ByteArray();

    ByteArray ba(array.at(0));
    for (unsigned int i = 1; i < array.size(); i++) {
        ba = (ba xor array.at(i));
    }

    return ba;
}
