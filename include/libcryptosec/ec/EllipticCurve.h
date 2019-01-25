#ifndef EllipticCurve_H_
#define EllipticCurve_H_

/* c++ library includes */
#include <string>

/* local includes */
#include <libcryptosec/BigInteger.h>

 /**
 * @brief Classe usada para representar curvas elípticas.
 * Esta classe possui funções para que os parâmetros das curvas sejam obtidos
 * ou gerados a partir de um arquivo em PEM/DER
 * @ingroup Util
 */
class EllipticCurve {

public:

	EllipticCurve();

	/**
	 * Cria uma curva elíptica a partir da descrição de seus parâmetros codificados em DER.
	 * @param encoded parâmetros de curva o formato DER.
	 */
	EllipticCurve(const ByteArray& encoded);

	/**
	 * Cria uma curva elíptica a partir da descrição de seus parâmetros codificados em PEM.
	 * @param encoded parâmetros de curva o formato PEM.
	 */
	EllipticCurve(const std::string& encoded);

	/**
	 * @brief Construtor de cópia.
	 *
	 * @param value A curva elíptica a ser copiada.
	 */
	EllipticCurve(const EllipticCurve& c);

	/**
	 * @brief Construtor para mover.
	 *
	 * @param value A curva elíptica a ser movida.
	 */
	EllipticCurve(EllipticCurve&& c);

	~EllipticCurve();

	/**
	 * @brief Operador de atribuição baseado em cópia.
	 *
	 * @param c A curva elíptica a ser copiada.
	 */
	EllipticCurve& operator=(const EllipticCurve& c);

	/**
	 * @brief Operador de atribuição baseado em move.
	 *
	 * @param c A curva elíptica a ser movida.
	 */
	EllipticCurve& operator=(EllipticCurve&& c);

	const BIGNUM* BN_a() const;

	const BIGNUM* BN_b() const;

	const BIGNUM* BN_p() const;

	const BIGNUM* BN_x() const;

	const BIGNUM* BN_y() const;

	const BIGNUM* BN_order() const;

	const BIGNUM* BN_cofactor() const;

	/*
	 * Getters and setters. Setter com Hex disponível para simplificação
	 * de código (caso mais comum).
	 */
	const BigInteger getA() const;
	void setA(const BigInteger& a);
	void setA(const std::string& hex);
	void setA(const char* hex);

	const BigInteger getB() const;
	void setB(const BigInteger& b);
	void setB(const std::string& hex);
	void setB(const char* hex);

	const BigInteger getCofactor() const;
	void setCofactor(const BigInteger& cofactor);
	void setCofactor(const std::string& hex);
	void setCofactor(const char* hex);

	const std::string getName() const;
	void setName(const std::string& name);

	const std::string getOid() const;
	void setOid(const std::string& oid);

	const BigInteger getOrder() const;
	void setOrder(const BigInteger& order);
	void setOrder(const std::string& hex);
	void setOrder(const char* hex);

	const BigInteger getP() const;
	void setP(const BigInteger& p);
	void setP(const std::string& hex);
	void setP(const char* hex);

	const BigInteger getX() const;
	void setX(const BigInteger& x);
	void setX(const std::string& hex);
	void setX(const char* hex);

	const BigInteger getY() const;
	void setY(const BigInteger& y);
	void setY(const std::string& hex);
	void setY(const char* hex);

protected:
	std::string oid, name;
	BigInteger a, b, p, x, y, order, cofactor;

	static const std::string notSpecified;

};
#endif /* EllipticCurve_H_ */
