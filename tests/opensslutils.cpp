#include "../util/openssl.h"

#include "../io/cryptoexception.h"

#include <c++utilities/chrono/datetime.h>
#include <c++utilities/conversion/stringconversion.h>
#include <c++utilities/tests/testutils.h>

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include <random>

using namespace std;
using namespace Util::OpenSsl;
using namespace CppUtilities;
using namespace CppUtilities::Literals;

using namespace CPPUNIT_NS;

/*!
 * \brief The OpenSslUtilsTests class tests the functions in the Util::OpenSsl namespace.
 */
class OpenSslUtilsTests : public TestFixture {
    CPPUNIT_TEST_SUITE(OpenSslUtilsTests);
    CPPUNIT_TEST(testComputeSha256Sum);
    CPPUNIT_TEST(testComputeHmacSha256);
    CPPUNIT_TEST(testGenerateRandomNumber);
    CPPUNIT_TEST(testComputeTOTP);
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp() override;
    void tearDown() override;

    void testComputeSha256Sum();
    void testComputeHmacSha256();
    void testGenerateRandomNumber();
    void testComputeTOTP();
};

CPPUNIT_TEST_SUITE_REGISTRATION(OpenSslUtilsTests);

void OpenSslUtilsTests::setUp()
{
}

void OpenSslUtilsTests::tearDown()
{
}

void OpenSslUtilsTests::testComputeSha256Sum()
{
    const char someString[] = "hello world";
    Sha256Sum sum = computeSha256Sum(reinterpret_cast<unsigned const char *>(someString), sizeof(someString));
    string sumAsHex;
    sumAsHex.reserve(64);
    for (unsigned char hashNumber : sum.data) {
        const string digits = numberToString(hashNumber, static_cast<unsigned char>(16));
        sumAsHex.push_back(digits.size() < 2 ? '0' : digits.front());
        sumAsHex.push_back(digits.back());
    }
    CPPUNIT_ASSERT_EQUAL("430646847E70344C09F58739E99D5BC96EAC8D5FE7295CF196B986279876BF9B"s, sumAsHex);
    // note that the termination char is hashed as well
}

void OpenSslUtilsTests::testComputeHmacSha256()
{
    // RFC 4231 Test Case 2
    const auto *key = reinterpret_cast<const unsigned char *>("Jefe");
    const auto keySize = std::size_t(4);
    const auto *data = reinterpret_cast<const unsigned char *>("what do ya want for nothing?");
    const auto dataSize = std::size_t(28);
    const auto hmac = computeHmacSha256(key, keySize, data, dataSize);
    auto hmacAsHex = std::string();
    hmacAsHex.reserve(64);
    for (auto hashNumber : hmac.data) {
        const auto digits = numberToString(hashNumber, static_cast<unsigned char>(16));
        hmacAsHex.push_back(digits.size() < 2 ? '0' : digits.front());
        hmacAsHex.push_back(digits.back());
    }
    CPPUNIT_ASSERT_EQUAL("5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC3843"s, hmacAsHex);
}

void OpenSslUtilsTests::testGenerateRandomNumber()
{
    CPPUNIT_ASSERT_EQUAL(static_cast<std::uint32_t>(0u), generateRandomNumber(0u, 0u));
    CPPUNIT_ASSERT_EQUAL(static_cast<std::uint32_t>(1u), generateRandomNumber(1u, 1u));
    const auto number = generateRandomNumber(5u, 7u);
    CPPUNIT_ASSERT(number == 5 || number == 6 || number == 7);
}

void OpenSslUtilsTests::testComputeTOTP()
{
    const auto urlDigits6Period30 = "otpauth://totp/foo%20bar?secret=ABCDABCDABCDABCD&period=30&digits=6&issuer=foo%20bar";
    const auto urlDigits8Period15 = "otpauth://totp/foo%20bar?secret=ABCDABCDABCDABCD&period=15&digits=8&issuer=foo%20bar";
    const auto urlSha256Digits8 = "otpauth://totp/foo%20bar?secret=ABCDABCDABCDABCD&period=30&digits=8&algorithm=SHA256";
    const auto urlSha512Digits10 = "otpauth://totp/foo%20bar?secret=ABCDABCDABCDABCD&period=30&digits=10&algorithm=SHA512";
    const auto urlInvalidSecret = "otpauth://totp/foo%20bar?secret=ABCDABCDABCDABC1&period=30&digits=10&algorithm=SHA512";
    const auto urlInvalidAlgo = "otpauth://totp/foo%20bar?secret=ABCDABCDABCDABCD&period=30&digits=10&algorithm=SHA513";

    const auto time = DateTime::fromDateAndTime(2026, 5, 2, 10, 52, 30);
    CPPUNIT_ASSERT_EQUAL("757702"s, computeTOTP(urlDigits6Period30, time).digits);
    CPPUNIT_ASSERT_EQUAL("41448963"s, computeTOTP(urlDigits8Period15, time).digits);
    CPPUNIT_ASSERT_EQUAL("10222808"s, computeTOTP(urlSha256Digits8, time).digits);
    CPPUNIT_ASSERT_EQUAL("0340892126"s, computeTOTP(urlSha512Digits10, time).digits);
    CPPUNIT_ASSERT_THROW(computeTOTP(urlInvalidSecret, time), ConversionException);
    CPPUNIT_ASSERT_THROW(computeTOTP(urlInvalidAlgo, time), Io::CryptoException);
}
