#include <libcryptosec/certificate/extension/ExtensionFactory.h>

#include <libcryptosec/certificate/extension/Extension.h>
#include <libcryptosec/certificate/extension/KeyUsageExtension.h>
#include <libcryptosec/certificate/extension/ExtendedKeyUsageExtension.h>
#include <libcryptosec/certificate/extension/AuthorityKeyIdentifierExtension.h>
#include <libcryptosec/certificate/extension/CRLDistributionPointsExtension.h>
#include <libcryptosec/certificate/extension/AuthorityInformationAccessExtension.h>
#include <libcryptosec/certificate/extension/BasicConstraintsExtension.h>
#include <libcryptosec/certificate/extension/CertificatePoliciesExtension.h>
#include <libcryptosec/certificate/extension/IssuerAlternativeNameExtension.h>
#include <libcryptosec/certificate/extension/SubjectAlternativeNameExtension.h>
#include <libcryptosec/certificate/extension/SubjectInformationAccessExtension.h>
#include <libcryptosec/certificate/extension/SubjectKeyIdentifierExtension.h>
#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/DecodeException.h>
#include <libcryptosec/exception/EncodeException.h>

ExtensionFactory::~ExtensionFactory() {
}

Extension* ExtensionFactory::getExtension(const X509_EXTENSION* ext) {
	Extension *oneExt = NULL;
	switch (Extension::getName(ext)) {
		case Extension::KEY_USAGE:
			oneExt = new KeyUsageExtension(ext);
			break;
		case Extension::EXTENDED_KEY_USAGE:
			oneExt = new ExtendedKeyUsageExtension(ext);
			break;
		case Extension::AUTHORITY_KEY_IDENTIFIER:
			oneExt = new AuthorityKeyIdentifierExtension(ext);
			break;
		case Extension::CRL_DISTRIBUTION_POINTS:
			oneExt = new CRLDistributionPointsExtension(ext);
			break;
		case Extension::AUTHORITY_INFORMATION_ACCESS:
			oneExt = new AuthorityInformationAccessExtension(ext);
			break;
		case Extension::BASIC_CONSTRAINTS:
			oneExt = new BasicConstraintsExtension(ext);
			break;
		case Extension::CERTIFICATE_POLICIES:
			oneExt = new CertificatePoliciesExtension(ext);
			break;
		case Extension::ISSUER_ALTERNATIVE_NAME:
			oneExt = new IssuerAlternativeNameExtension(ext);
			break;
		case Extension::SUBJECT_ALTERNATIVE_NAME:
			oneExt = new SubjectAlternativeNameExtension(ext);
			break;
		case Extension::SUBJECT_INFORMATION_ACCESS:
			oneExt = new SubjectInformationAccessExtension(ext);
			break;
		case Extension::SUBJECT_KEY_IDENTIFIER:
			oneExt = new SubjectKeyIdentifierExtension(ext);
			break;
		default:
			oneExt = new Extension(ext);
			break;
	}
	return oneExt;
}
