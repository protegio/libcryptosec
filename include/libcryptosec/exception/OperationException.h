#ifndef OPERATIONEXCEPTION_H_
#define OPERATIONEXCEPTION_H_

#include <libcryptosec/exception/LibCryptoSecException.h>

#include <openssl/err.h>

class OperationException : public LibCryptoSecException
{
public:

	OperationException(const std::string& where)
    {
    	this->where = where;
    }

	virtual ~OperationException() throw () {}

	virtual std::string getMessage() const
	{
		return "Operation error: " + this->where;
	}

    virtual std::string toString() const
    {
    	return "Operation error: " + this->where;
    }
};

#endif /*OPERATIONEXCEPTION_H_*/
