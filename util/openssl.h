#ifndef PASSWORD_FILE_UTIL_OPENSSL_H
#define PASSWORD_FILE_UTIL_OPENSSL_H

#include "../global.h"

#include <c++utilities/chrono/timespan.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace CppUtilities {
class DateTime;
}

namespace Util {

namespace OpenSsl {

struct Sha256Sum {
    static constexpr std::size_t size = 32;
    unsigned char data[size] = { 0 };
};

struct TOTP {
    std::string digits;
    CppUtilities::TimeSpan period;
    CppUtilities::TimeSpan remaining;
};

PASSWORD_FILE_EXPORT void init();
PASSWORD_FILE_EXPORT void clean();
PASSWORD_FILE_EXPORT Sha256Sum computeSha256Sum(const unsigned char *buffer, std::size_t size);
PASSWORD_FILE_EXPORT Sha256Sum computeHmacSha256(const unsigned char *key, std::size_t keySize, const unsigned char *data, std::size_t dataSize);
PASSWORD_FILE_EXPORT std::uint32_t generateRandomNumber(std::uint32_t min, std::uint32_t max);
PASSWORD_FILE_EXPORT TOTP computeTOTP(std::string_view url, CppUtilities::DateTime time);

} // namespace OpenSsl
} // namespace Util

#endif // PASSWORD_FILE_UTIL_OPENSSL_H
