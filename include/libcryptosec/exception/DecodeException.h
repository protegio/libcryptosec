#ifndef DECODEEXCEPTION_H_
#define DECODEEXCEPTION_H_

#include <openssl/err.h>

#include <libcryptosec/exception/LibCryptoSecException.h>

class DecodeException : public LibCryptoSecException
{
public:

	DecodeException(const std::string& where)
    {
    	this->where = where;
    }

	virtual ~DecodeException() throw () {}

	virtual std::string getMessage() const
	{
		return "Decode error: " + this->where;
	}

    virtual std::string toString() const
    {
    	return "Decode error: " + this->where;
    }
};

#endif /*DECODEEXCEPTION_H_*/
