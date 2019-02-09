#ifndef ENCODEEXCEPTION_H_
#define ENCODEEXCEPTION_H_

#include <openssl/err.h>

#include <libcryptosec/exception/LibCryptoSecException.h>

class EncodeException : public LibCryptoSecException
{
public:
	EncodeException(const std::string& where)
    {
    	this->where = where;
    }

	virtual ~EncodeException() throw () {}

	virtual std::string getMessage() const
	{
		return "Encode error: " + this->where;
	}

    virtual std::string toString() const
    {
    	return "Encode error: " + this->where;
    }
};

#endif /*ENCODEEXCEPTION_H_*/
