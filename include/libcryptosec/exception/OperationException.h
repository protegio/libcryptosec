#ifndef OPERATIONEXCEPTION_H_
#define OPERATIONEXCEPTION_H_

#include <libcryptosec/exception/LibCryptoSecException.h>

#include <openssl/err.h>

class OperationException : public LibCryptoSecException
{
public:
	enum ErrorCode
	{
		UNKNOWN = 0,
	};

	OperationException(const std::string& where)
    {
    	this->where = where;
    	this->errorCode = OperationException::UNKNOWN;
    }

	OperationException(OperationException::ErrorCode errorCode, const std::string& where)
    {
    	this->where = where;
    	this->errorCode = errorCode;
    }

	virtual ~OperationException() throw () {}

	virtual std::string getMessage() const
	{
		return (OperationException::errorCode2Message(this->errorCode));
	}

    virtual std::string toString() const
    {
    	std::string ret;
    	if (this->errorCode == OperationException::UNKNOWN)
    	{
    		ret = "EncodeException. Called by: " + this->where + ".";
    	}
    	else
    	{
    		ret = "EncodeException: " + OperationException::errorCode2Message(this->errorCode) + ". Called by: " + this->where + ".";
    	}
    	return ret;
    }

    virtual OperationException::ErrorCode getErrorCode()
    {
    	return this->errorCode;
    }

    static std::string errorCode2Message(OperationException::ErrorCode errorCode)
    {
    	std::string ret;
    	switch (errorCode) {
    		case OperationException::UNKNOWN:
    			ret = "Unknown error";
    			break;
    	}
    	return ret;
    }

protected:
    OperationException::ErrorCode errorCode;
};

#endif /*OPERATIONEXCEPTION_H_*/
