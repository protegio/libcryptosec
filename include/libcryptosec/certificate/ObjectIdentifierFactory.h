#ifndef OBJECTIDENTIFIERFACTORY_H_
#define OBJECTIDENTIFIERFACTORY_H_

#include <openssl/objects.h>

#include "ObjectIdentifier.h"

#include <libcryptosec/exception/CertificationException.h>

class ObjectIdentifierFactory
{
public:
	static ObjectIdentifier getObjectIdentifier(std::string oid);
	static ObjectIdentifier getObjectIdentifier(int nid);
	static ObjectIdentifier createObjectIdentifier(std::string oid, std::string name);
};

#endif /*OBJECTIDENTIFIERFACTORY_H_*/
