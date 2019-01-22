#ifndef INCLUDE_LIBCRYPTOSEC_EXCEPTION_SYMMETRICKEYEXCEPTION_H_
#define INCLUDE_LIBCRYPTOSEC_EXCEPTION_SYMMETRICKEYEXCEPTION_H_

#include <libcryptosec/exception/LibCryptoSecException.h>

#include <string>


class SymmetricKeyException : public LibCryptoSecException
{
public:
	enum ErrorCode
	{
		UNKNOWN,
		INVALID_ALGORITHM,
	};

    SymmetricKeyException(const std::string& where)
    {
    	this->where = where;
    	this->errorCode = SymmetricKeyException::UNKNOWN;
    }

    SymmetricKeyException(SymmetricKeyException::ErrorCode errorCode, const std::string& where)
    {
    	this->where = where;
    	this->errorCode = errorCode;
    }

	virtual ~SymmetricKeyException() throw () {}

	virtual std::string getMessage() const
	{
		return SymmetricKeyException::errorCode2Message(this->errorCode);
	}

    virtual std::string toString() const
    {
    	std::string ret;
    	if (this->errorCode == SymmetricKeyException::UNKNOWN)
    	{
    		ret = "SymmetricKeyException. Called by: " + this->where + ".";
    	}
    	else
    	{
    		ret = "SymmetricKeyException: " + SymmetricKeyException::errorCode2Message(this->errorCode) + ". Called by: " + this->where + ".";
    	}
    	return ret;
    }

    virtual SymmetricKeyException::ErrorCode getErrorCode()
    {
    	return this->errorCode;
    }

    static std::string errorCode2Message(SymmetricKeyException::ErrorCode errorCode)
    {
    	std::string ret;
    	switch (errorCode)
    	{
    		case SymmetricKeyException::UNKNOWN:
    			ret = "Unknown error";
    			break;
    		case SymmetricKeyException::INVALID_ALGORITHM:
    			ret = "Invalid symmetric algorithm";
    			break;
    	}
    	return ret;
    }

protected:

	SymmetricKeyException::ErrorCode errorCode;
};



#endif /* INCLUDE_LIBCRYPTOSEC_EXCEPTION_SYMMETRICKEYEXCEPTION_H_ */
