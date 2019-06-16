#ifndef BIGINTEGER_H_
#define BIGINTEGER_H_

#include <openssl/bn.h>
#include <openssl/asn1.h>

#include <string>

class ByteArray;

/**
 * @ingroup Util
 */

/**
 * @brief Classe usada para representar números grandes. 
 * A limitação do tamanho do número depende da memória disponível
 */
class BigInteger
{
public:

	/**
	 * @brief Construtor padrão.
	 *
	 * Inicializa o objeto com o valor 0.
	 */
	BigInteger();
	
	/**
	 * @brief Construtor de inicialização por estrutura BIGNUM do OpenSSL.
	 *
	 * @param value Ponteiro para estrutra BIGNUM.
	 */
	BigInteger(const BIGNUM* value);
	
	/**
	 * @brief Construtor de inicialização por valor long.
	 *
	 * @param value Valor a ser atribuído ao objeto.
	 */
	BigInteger(int64_t value);
	BigInteger(uint64_t value);
	BigInteger(int32_t value);
	BigInteger(uint32_t value);

	/**
	 * @brief Construtor de inicialização por valor estrutura ASN1_INTEGER do OpenSSL.
	 *
	 * @param value Ponteiro para estrutura ASN1_INTEGER.
	 */
	BigInteger(const ASN1_INTEGER* value);
	
	/**
	 * @brief Construtor de inicialização por ByteArray.
	 *
	 * Esse construtor permite construir um BigInteger a partir de um inteiro
	 * representado por um array de bytes no formato big-endian.
	 *
	 * @param value O valor do inteiro representado em um array de bytes no formato big-endian.
	 */
	BigInteger(const ByteArray& value);

	/**
	 * @brief Construtor de inicialização por string de um número inteiro.
	 *
	 * @param value String contendo um número inteiro.
	 * @param base A base numérica usada para representar o número inteiro.
	 */
	BigInteger(const std::string& value, uint32_t base = 10);
	BigInteger(const char* value, uint32_t base = 10);

	/**
	 * @brief Construtor de cópia.
	 *
	 * @param value Objeto a ser copiado.
	 */
	BigInteger(const BigInteger& value);
	
	/**
	 * Construtor de inicialização por movimentação de atributos.
	 *
	 * @param value referência para um objeto BigInteger.
	 */
	BigInteger(BigInteger&& value);

	/**
	 * Destrutor padrão.
	 */
	virtual ~BigInteger();

	/**
	 * @brief Operador de atribuição por cópia.
	 *
	 * @param value Valor que será atribuído.
	 *
	 * @return O próprio objeto.
	 */
	BigInteger& operator=(const BigInteger& value);

	/**
	 * @brief Operador de atribuição por movimentação de atributos.
	 *
	 * @param value Valor a ser atribuído.
	 *
	 * @return O próprio objeto.
	 */
	BigInteger& operator=(BigInteger&& value);

	/**
	 * @brief Atribui o valor ao objeto.
	 *
	 * @param value Valor a ser atribuído.
	 */
	void setInt64(int64_t value);
	void setUint64(uint64_t value);

	/**
	 * @return O valor do inteiro no formato int32_t.
	 */
	int64_t toInt64() const;
	int32_t toInt32() const;

	/**
	 * @return Retorna true se o inteiro é negativo, false caso contrário.
	 */
	bool isNegative() const;

	/**
	 * @return A estrutura ASN1_INTEGER que representa o valor inteiro. A estrutura deve
	 * 	ser desalocada por quem chamou a função com a função ASN1_INTEGER_free();
	 */
	ASN1_INTEGER* toAsn1Integer() const;

	/**
	 * @return O valor do inteiro representado em um array de bytes no formato big-endian.
	 */
	ByteArray toByteArray() const;

	/**
	 * @return A representação hexadecimal do inteiro.
	 */
	std::string toHex() const;
	
	/**
	 * @return A representação decimal do inteiro.
	 */
	std::string toDec() const;

	/**
	 * @brief Atribui o valor representado em hexadecimal.
	 *
	 * Não utilizar o prefixo "0x".
	 *
	 * @param hex O valor inteiro em hexadecimal.
	 */
	void setHexValue(const std::string& hex);

	/**
	 * @brief Atribui o valor representado em decimal.
	 *
	 * @param hex O valor inteiro em decimal.
	 */
	void setDecValue(const std::string& dec);

	/**
	 * @brief Atribui ou remove o sinal de negativo.
	 * @param bool true se negativo, false se positivo.
	 */
	void setNegative(bool neg = true) noexcept;
	
	/**
	 * @return O tamanho em bits do inteiro.
	 */
	uint32_t bitSize() const;
	
	/**
	 * Soma os valores inteiros entre dois BigIntegers.
	 * @param a referência para objeto constante BigInteger.
	 * @return referência para objeto BigInteger com o resultado da soma.
	 * @throw BigIntegerException no caso de um erro interno do OpenSSL.
	 */
	BigInteger& add(const BigInteger& a);
	BigInteger operator+(const BigInteger& c) const;
	BigInteger& operator+=(const BigInteger& c);

	/**
	 * Subtração entre os valores inteiros de dois BigIntegers.
	 * @param a referência para objeto constante BigInteger.
	 * @return referência para objeto BigInteger com o resultado da subtração.
	 * @throw BigIntegerException no caso de um erro interno do OpenSSL.
	 */
	BigInteger& sub(const BigInteger& a);
	BigInteger operator-(const BigInteger& c) const;

	/**
	 * Multiplação entre os valores inteiros de doi BigIntegers.
	 */
	BigInteger& mul(const BigInteger& a);
	BigInteger operator*(const BigInteger& a) const;

	/**
	 * Divisão entre os valores inteiros de doi BigIntegers.
	 */
	BigInteger& div(const BigInteger& a);
	BigInteger operator/(const BigInteger& a) const;

	/**
	 * @brief Operação modular.
	 *
	 * @param divisor O divisor da operação modular.
	 *
	 * @return O resultado da operação modular.
	 */
	BigInteger mod(const BigInteger& divisor) const;
	BigInteger operator%(const BigInteger& divisor) const;

	/**
	 * @brief Operação de comparação.
	 *
	 * @param bigInteger Valor para ser comparado.
	 *
	 * @return Retorna 0 se for igual ao valor passado, 1 se for maior e -1 se for menor.
	 */
	int compare(const BigInteger& bigInteger) const noexcept;

	/**
	 * @brief Operador de igualdade.
	 *
	 * @param bigInteger Valor para ser comparado.
	 *
	 * @return Retorna true se for igual, false caso contrário.
	 */
	bool operator==(const BigInteger& c) const;

	/**
	 * @brief Operador de desigualdade.
	 *
	 * @param bigInteger Valor para ser comparado.
	 *
	 * @return Retorna false se for igual, true caso contrário.
	 */
	bool operator!=(const BigInteger& bigInteger) const;
	
	/**
	 * @brief Operador de maior.
	 *
	 * @param bigInteger Valor para ser comparado.
	 *
	 * @return Retorna true se for maior que \p bigInteger, false caso contrário.
	 */
	bool operator>(const BigInteger& bigInteger) const;

	/**
	 * @brief Operador de maior ou igual.
	 *
	 * @param bigInteger Valor para ser comparado.
	 *
	 * @return Retorna true se for maior ou igual que \p bigInteger, false caso contrário.
	 */
	bool operator>=(const BigInteger& bigInteger) const;

	/**
	 * @brief Operador de menor.
	 *
	 * @param bigInteger Valor para ser comparado.
	 *
	 * @return Retorna true se for menor que \p bigInteger, false caso contrário.
	 */
	bool operator<(const BigInteger& bigInteger) const;

	/**
	 * @brief Operador de menor ou igual.
	 *
	 * @param bigInteger Valor para ser comparado.
	 *
	 * @return Retorna true se for menor ou igual que \p bigInteger, false caso contrário.
	 */
	bool operator<=(const BigInteger& bigInteger) const;

	/**
	 * @brief Operador de negação.
	 *
	 * @return Retorna false se o valor for 0, true caso contrário.
	 */
	bool operator!() const;

	/**
	 * @brief Operador de "ou" lógico.
	 */
	bool operator||(const BigInteger& c) const;

	/**
	 * @brief Operador "e" lógico.
	 *
	 * @param bigInteger Valor para realizar a operação lógica.
	 *
	 * @return Retorna true se \p bigInteger for diferente
	 */
	bool operator&&(const BigInteger& c) const;

	/**
	 * @return O ponteiro para estrutura interna BIGNUM.
	 */
	const BIGNUM* getSslObject() const;

	/**
	 * @return Uma cópia da estrutura interna BIGNUM.
	 */
	BIGNUM* toSslObject() const;

protected:
	BIGNUM* bigInt;
};


#endif /*BIGINTEGER_H_*/
