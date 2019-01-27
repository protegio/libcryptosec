#ifndef BYTEARRAYEXCEPTION_H_
#define BYTEARRAYEXCEPTION_H_

#include <libcryptosec/exception/LibCryptoSecException.h>

#include <openssl/err.h>

class ByteArrayException : public LibCryptoSecException
{
public:
	enum ErrorCode
	{
		UNKNOWN = 0,
		MEMORY_ALLOC = 1,
		INTERNAL_ERROR = 3,
		UNSIGNED_LONG_OVERFLOW = 4,
		OUT_OF_BOUNDS = 5,
		RANDOM_ERROR = 6,
	};
	
	ByteArrayException(ErrorCode errorCode = UNKNOWN, std::string where = "")
	{
		this->where = where;
		this->errorCode = errorCode;
	}
	virtual ~ByteArrayException() throw() {}
	
	virtual std::string getMessage() const
	{
		return (ByteArrayException::errorCode2Message(this->errorCode));
	}
	
    virtual std::string toString() const
    {
    	std::string ret;
    	if (this->errorCode == ByteArrayException::UNKNOWN)
    	{
    		ret = "BigIntegerException. Called by: " + this->where + ".";
    	}
    	else
    	{
    		ret = "BigIntegerException: " + ByteArrayException::errorCode2Message(this->errorCode) + ". Called by: " + this->where + ".";
    	}
    	return ret;
    }
    
    virtual ErrorCode getErrorCode()
    {
    	return this->errorCode;
    }
    
    static std::string errorCode2Message(ErrorCode errorCode)
    {
    	std::string ret;
    	switch (errorCode)
    	{
    		case UNKNOWN:
    			ret = "Unknown error";
    			break;
    		case MEMORY_ALLOC:
    			ret = "Memory allocation error";
    			break;
    		case INTERNAL_ERROR:
    			ret = "OpenSSL BIGNUM operation internal error";
    			break;
    		case UNSIGNED_LONG_OVERFLOW:
    			ret = "Big Integer can not be represented as unsigned long";
    			break;
    		case OUT_OF_BOUNDS:
    		    ret = "Out of bounds";
    		    break;
    		case RANDOM_ERROR:
    			ret = "Random error";
    			break;
    	}
    	return ret;
    }
    
protected:
	ErrorCode errorCode;
};

#endif /*BYTEARRAYEXCEPTION_H_*/
