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
	 * Construtor padrão.
	 * Cria um objeto BigInteger com o valor inteiro 0.
	 * @throw BigIntegerException no caso de falta de memória ao criar o BigInteger.
	 */
	BigInteger();
	
	/**
	 * BigInteger a partir de um estrutura BIGNUM do OpenSSL.
	 * @param bn ponteiro para estrutra constante BIGNUM.
	 * @throw BigIntegerException no caso de erro interno do OpenSSL ao criar o BigInteger.
	 * */
	BigInteger(BIGNUM const* bn);
	
	/**
	 * BigInteger a partir de um tipo primitivo (unsigned long).
	 * @param val valor inteiro.
	 * @throw BigIntegerException no caso de falta de memória ao criar o BigInteger. 
	 * */
	BigInteger(long val);
	BigInteger(int val);
	
	/**
	 * BigInteger a partir de uma estrutura ASN1_INTEGER do OpenSSL.
	 * @param val ponteiro para estrutura ASN1_INTEGER.
	 * @throw BigIntegerException no caso de falta de memória ao criar o BigInteger.
	 * */
	BigInteger(const ASN1_INTEGER* val);
	
	/**
	 * Construtor de inicialização com ByteArray.
	 * @param val referência para objeto constante ByteArray.
	 * @throw BigIntegerException no caso de falta de memória ao criar o BigInteger ou devido a um erro interno do OpenSSL.
	 * */
	BigInteger(const ByteArray& b);
	
	/**
	 * BigInteger a partir do string de um número inteiro na base decimal.
	 * @param dec string contendo um número inteiro em base 10.
	 * @throw BigIntegerException no caso de falta de memória ao criar o BigInteger.
	 * */
	BigInteger(const std::string& dec);
	BigInteger(const char* dec);

	/**
	 * Construtor de cópia.
	 * @param b referência para um objeto BigInteger.
	 * @throw BigIntegerException no caso de falta de memória ao criar o BigInteger.
	 * */
	BigInteger(const BigInteger& b);
	
	/**
	 * Construtor de move.
	 * @param b referência para um objeto BigInteger.
	 * @throw BigIntegerException no caso de falta de memória ao criar o BigInteger.
	 * */
	BigInteger(BigInteger&& b);

	/**
	 * Destrutor padrão
	 * */
	virtual ~BigInteger();

	/**
	 * Operador de atribuição.
	 * @param c referência para objeto constante BigInteger.
	 * @return referência para objeto BigInteger.
	 * @throw BigIntegerException no caso de um erro interno do OpenSSL.
	 * */
	BigInteger& operator=(long c);
	BigInteger& operator=(const BigInteger& c);
	BigInteger& operator=(BigInteger&& c);

	/**
	 * Define o valor inteiro de um BigInteger. Se nenhum valor é passado, define o valor zero.
	 * @param val valor inteiro.
	 * @throw BigIntegerException no caso de um erro interno do OpenSSL.
	 * */
	void setValue(long val = 0);

	/**
	 * Retorna o valor inteiro correspondente do BigInteger.
	 * @return valor inteiro do BigInteger.
	 * @throw BigIntegerException caso o valor do BigInteger não possa ser representado em um unsigned long (overflow).
	 * */
	double getValue() const;

	/**
	 * Retorna se o BigInteger é negativo.
	 * @return true se o BigInteger é negativo, false caso contrário.
	 * */
	bool isNegative() const;

	/**
	 * Retorna estrutura ASN1_INTEGER com o valor do BigInteger.
	 * @return estrutura ASN1_INTEGER.
	 * @throw BigIntegerException no caso de falta de memória ao criar o ASN1_INTEGER.
	 * */
	ASN1_INTEGER* getASN1Value() const;

	/**
	 * Retorna ponteiro para um objeto ByteArray com o valor do BigInteger. 
	 * O objeto ByteArray tem codificação mpi (inclui sinal) e deve ser deletado.
	 * @return ponteiro para objeto ByteArray.
	 * @throw BigIntegerException no caso de falta de memória ao criar o ByteArray.
	 * */
	ByteArray getBinValue() const;

	/**
	 * Retorna ponteiro para estrutura constante BIGNUM membro de BigInteger.
	 * @return ponteiro para estrutura constante BIGNUM.
	 * */
	const BIGNUM* getBIGNUM() const;

	/**
	 * Retorna string com valor do BigInteger em base 16.
	 * @return string com valor inteiro.
	 * */
	std::string toHex() const;
	
	/**
	 * Retorna string com valor do BigInteger em base 10.
	 * @return string com valor inteiro.
	 * */	
	std::string toDec() const;

	/**
	 * Define o valor inteiro em base 16 de um BigInteger. Não utilizar string "0x" para identificar base 16.
	 * @param hex valor inteiro.
	 * @throw BigIntegerException no caso de um erro interno do OpenSSL.
	 * */
	void setHexValue(const std::string& hex); //nao utilizar "0x"
	void setHexValue(const char* hex);

	/**
	* Define o valor inteiro em base 10 de um BigInteger. Não utilizar string "0x" para identificar base 16.
	* @param dec valor inteiro.
	* @throw BigIntegerException no caso de um erro interno do OpenSSL.
	* */
	void setDecValue(const std::string& dec);
	void setDecValue(const char* dec);

	/**
	 * Define um valor inteiro randômico (positivo ou negativo).
	 * @param numBits número de bits do BigInteger. Se nenhum parâmetro é passado, assume-se numBits = 64.
	 * @throw BigIntegerException no caso de um erro interno do OpenSSL.
	 * */
	void setRandValue(int numBits = 64);

	/**
	 * Define o sinal do BigInteger.
	 * @param bool true se negativo, false se positivo. Se nenhum parâmetro é passado, assume-se negativo.
	 * */
	void setNegative(bool neg = true);
	
	/**
	 * Retorna o tamanho do valor inteiro do BigInteger em bits.
	 * @return tamanho do BigInteger
	 * */
	int size() const;
	
	/**
	 * Soma os valores inteiros entre dois BigIntegers.
	 * @param a referência para objeto constante BigInteger.
	 * @return referência para objeto BigInteger com o resultado da soma.
	 * @throw BigIntegerException no caso de um erro interno do OpenSSL.
	 * */
	BigInteger& add(const BigInteger& a);
	BigInteger& add(long a);
	BigInteger operator+(const BigInteger& c) const;
	BigInteger operator+(long c) const;
	BigInteger& operator+=(const BigInteger& c);
	BigInteger& operator+=(long c);

	/**
	 * Subtração entre os valores inteiros de dois BigIntegers.
	 * @param a referência para objeto constante BigInteger.
	 * @return referência para objeto BigInteger com o resultado da subtração.
	 * @throw BigIntegerException no caso de um erro interno do OpenSSL.
	 * */
	BigInteger& sub(const BigInteger& a);
	BigInteger& sub(long a);
	BigInteger operator-(const BigInteger& c) const;
	BigInteger operator-(long c) const;

	/**
	 * Multiplação entre os valores inteiros de doi BigIntegers.
	 */
	BigInteger& mul(const BigInteger& a);
	BigInteger& mul(long a);
	BigInteger operator*(const BigInteger& a) const;
	BigInteger operator*(long c) const;

	/**
	 * Divisão entre os valores inteiros de doi BigIntegers.
	 */
	BigInteger& div(const BigInteger& a);
	BigInteger& div(long a);
	BigInteger operator/(const BigInteger& a) const;
	BigInteger operator/(long c) const;

	/**
	 * Módulo entre os valores inteiros de doi BigIntegers.
	 */
	BigInteger& mod(const BigInteger& a);
	BigInteger& mod(long a);
	BigInteger operator%(const BigInteger& a) const;
	BigInteger operator%(long c) const;
	
	int compare(const BigInteger& a) const;

	/**
	 * Operadores de comparação.
	 */
	bool operator==(const BigInteger& c) const;
	bool operator==(long c) const;

	bool operator!=(const BigInteger& c) const;
	bool operator!=(long c) const;
	
	bool operator>(const BigInteger& c) const;
	bool operator>(long c) const;

	bool operator>=(const BigInteger& c) const;
	bool operator>=(long c) const;
	
	bool operator<(const BigInteger& c) const;
	bool operator<(long c) const;

	bool operator<=(const BigInteger& c) const;
	bool operator<=(long c) const;

	/**
	 * Operadores lógicos.
	 */
	bool operator!() const;

	bool operator||(const BigInteger& c) const;
	bool operator||(long c) const;

	bool operator&&(const BigInteger& c) const;
	bool operator&&(long c) const;

protected:
	BIGNUM* bigInt;
};

BigInteger operator+(long c, const BigInteger& d);
BigInteger operator-(long c, const BigInteger& d);


#endif /*BIGINTEGER_H_*/
