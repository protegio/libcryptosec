#ifndef NULLPOINTEREXCEPTION_H_
#define NULLPOINTEREXCEPTION_H_

#include <openssl/err.h>

#include <libcryptosec/exception/LibCryptoSecException.h>

class NullPointerException : public LibCryptoSecException
{
public:
	NullPointerException(const std::string& where = "")
    {
    	this->where = where;
    }

	virtual ~NullPointerException() throw () {}

	virtual std::string getMessage() const
	{
		return "NullPointerException: " + this->where;
	}

    virtual std::string toString() const
    {
    	return "NullPointerException: " + this->where;
    }
};

#endif /*NULLPOINTEREXCEPTION_H_*/
