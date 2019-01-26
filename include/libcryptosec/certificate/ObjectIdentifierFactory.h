#ifndef OBJECTIDENTIFIERFACTORY_H_
#define OBJECTIDENTIFIERFACTORY_H_

#include <libcryptosec/certificate/ObjectIdentifier.h>

class ObjectIdentifierFactory
{
public:
	static ObjectIdentifier getObjectIdentifier(const std::string& oid);
	static ObjectIdentifier getObjectIdentifier(int nid);
	static ObjectIdentifier createObjectIdentifier(const std::string& oid, const std::string& name);
};

#endif /*OBJECTIDENTIFIERFACTORY_H_*/
