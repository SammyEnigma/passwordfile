#include "../io/cryptoexception.h"
#include "../io/entry.h"
#include "../io/passwordfile.h"

#include <c++utilities/tests/testutils.h>

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

using namespace std;
using namespace Io;
using namespace TestUtilities::Literals;

using namespace CPPUNIT_NS;

/*!
 * \brief The PasswordFileTests class tests the Io::PasswordFile class.
 */
class PasswordFileTests : public TestFixture {
    CPPUNIT_TEST_SUITE(PasswordFileTests);
    CPPUNIT_TEST(testReading);
    CPPUNIT_TEST(testBasicWriting);
    CPPUNIT_TEST(testExtendedWriting);
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp() override;
    void tearDown() override;

    void testReading();
    void testReading(const string &context, const string &testfile1path, const string &testfile1password, const string &testfile2,
        const string &testfile2password, bool testfile2Mod, bool extendedHeaderMod);
    void testBasicWriting();
    void testExtendedWriting();
};

CPPUNIT_TEST_SUITE_REGISTRATION(PasswordFileTests);

void PasswordFileTests::setUp()
{
}

void PasswordFileTests::tearDown()
{
}

/*!
 * \brief Tests reading the testfiles testfile{1,2}.pwmgr.
 */
void PasswordFileTests::testReading()
{
    testReading(
        "read", TestUtilities::testFilePath("testfile1.pwmgr"), "123456", TestUtilities::testFilePath("testfile2.pwmgr"), string(), false, false);
}

void PasswordFileTests::testReading(const string &context, const string &testfile1path, const string &testfile1password, const string &testfile2,
    const string &testfile2password, bool testfile2Mod, bool extendedHeaderMod)
{
    PasswordFile file;

    // open testfile 1 ...
    file.setPath(testfile1path);
    file.open(PasswordFileOpenFlags::ReadOnly);

    CPPUNIT_ASSERT_EQUAL_MESSAGE(context, !testfile1password.empty(), file.isEncryptionUsed());
    // attempt to decrypt using a wrong password
    file.setPassword(testfile1password + "asdf");
    if (!testfile1password.empty()) {
        CPPUNIT_ASSERT_THROW(file.load(), CryptoException);
    }
    // attempt to decrypt using the correct password
    file.setPassword(testfile1password);
    file.load();
    // test root entry
    const NodeEntry *const rootEntry = file.rootEntry();
    CPPUNIT_ASSERT_EQUAL("testfile1"s, rootEntry->label());
    CPPUNIT_ASSERT_EQUAL(4_st, rootEntry->children().size());

    // test testaccount1
    CPPUNIT_ASSERT_EQUAL("testaccount1"s, rootEntry->children()[0]->label());
    CPPUNIT_ASSERT_EQUAL(EntryType::Account, rootEntry->children()[0]->type());
    CPPUNIT_ASSERT_EQUAL("pin"s, static_cast<AccountEntry *>(rootEntry->children()[0])->fields().at(0).name());
    CPPUNIT_ASSERT_EQUAL("123456"s, static_cast<AccountEntry *>(rootEntry->children()[0])->fields().at(0).value());
    CPPUNIT_ASSERT_EQUAL(FieldType::Password, static_cast<AccountEntry *>(rootEntry->children()[0])->fields().at(0).type());
    CPPUNIT_ASSERT(
        static_cast<AccountEntry *>(rootEntry->children()[0])->fields().at(0).tiedAccount() == static_cast<AccountEntry *>(rootEntry->children()[0]));
    CPPUNIT_ASSERT_EQUAL(FieldType::Normal, static_cast<AccountEntry *>(rootEntry->children()[0])->fields().at(1).type());
    CPPUNIT_ASSERT_THROW(static_cast<AccountEntry *>(rootEntry->children()[0])->fields().at(2), out_of_range);

    // test testaccount2
    CPPUNIT_ASSERT_EQUAL("testaccount2"s, rootEntry->children()[1]->label());
    CPPUNIT_ASSERT_EQUAL(EntryType::Account, rootEntry->children()[1]->type());
    CPPUNIT_ASSERT_EQUAL(0_st, static_cast<AccountEntry *>(rootEntry->children()[1])->fields().size());

    // test testcategory1
    CPPUNIT_ASSERT_EQUAL("testcategory1"s, rootEntry->children()[2]->label());
    CPPUNIT_ASSERT_EQUAL(EntryType::Node, rootEntry->children()[2]->type());
    const NodeEntry *const category = static_cast<NodeEntry *>(rootEntry->children()[2]);
    CPPUNIT_ASSERT_EQUAL(3_st, category->children().size());
    CPPUNIT_ASSERT_EQUAL(EntryType::Node, category->children()[2]->type());
    CPPUNIT_ASSERT_EQUAL(2_st, static_cast<NodeEntry *>(category->children()[2])->children().size());

    // test testaccount3
    CPPUNIT_ASSERT_EQUAL("testaccount3"s, rootEntry->children()[3]->label());

    if (extendedHeaderMod) {
        CPPUNIT_ASSERT_EQUAL("foo"s, file.extendedHeader());
    } else {
        CPPUNIT_ASSERT_EQUAL(""s, file.extendedHeader());
    }
    CPPUNIT_ASSERT_EQUAL(""s, file.encryptedExtendedHeader());

    // open testfile 2
    file.setPath(testfile2);
    file.open(PasswordFileOpenFlags::ReadOnly);

    CPPUNIT_ASSERT_EQUAL(!testfile2password.empty(), file.isEncryptionUsed());
    file.setPassword(testfile2password);
    file.load();
    const NodeEntry *const rootEntry2 = file.rootEntry();
    if (testfile2Mod) {
        CPPUNIT_ASSERT_EQUAL("testfile2 - modified"s, rootEntry2->label());
        CPPUNIT_ASSERT_EQUAL(2_st, rootEntry2->children().size());
        CPPUNIT_ASSERT_EQUAL("newAccount"s, rootEntry2->children()[1]->label());
    } else {
        CPPUNIT_ASSERT_EQUAL("testfile2"s, rootEntry2->label());
        CPPUNIT_ASSERT_EQUAL(1_st, rootEntry2->children().size());
    }
    if (extendedHeaderMod) {
        CPPUNIT_ASSERT_EQUAL("foo"s, file.extendedHeader());
        CPPUNIT_ASSERT_EQUAL("bar"s, file.encryptedExtendedHeader());
    } else {
        CPPUNIT_ASSERT_EQUAL(""s, file.extendedHeader());
        CPPUNIT_ASSERT_EQUAL(""s, file.encryptedExtendedHeader());
    }
}

/*!
 * \brief Tests writing (and reading again) using basic features.
 */
void PasswordFileTests::testBasicWriting()
{
    const string testfile1 = TestUtilities::workingCopyPath("testfile1.pwmgr");
    const string testfile2 = TestUtilities::workingCopyPath("testfile2.pwmgr");
    PasswordFile file;

    // resave testfile 1
    file.setPath(testfile1);
    file.open();
    file.setPassword("123456");
    file.load();
    file.doBackup();
    file.save(PasswordFileSaveFlags::Compression);

    // resave testfile 2
    file.setPath(testfile2);
    file.open();
    file.load();
    file.rootEntry()->setLabel("testfile2 - modified");
    new AccountEntry("newAccount", file.rootEntry());
    file.setPassword("654321");
    file.doBackup();
    file.save(PasswordFileSaveFlags::Encryption);

    // check results using the reading test
    testReading("basic writing", testfile1, string(), testfile2, "654321", true, false);

    // check backup files
    testReading("basic writing", testfile1 + ".backup", "123456", testfile2 + ".backup", string(), false, false);
}

/*!
 * \brief Tests writing (and reading again) using extended features.
 */
void PasswordFileTests::testExtendedWriting()
{
    const string testfile1 = TestUtilities::workingCopyPath("testfile1.pwmgr");
    const string testfile2 = TestUtilities::workingCopyPath("testfile2.pwmgr");
    PasswordFile file;

    // resave testfile 1
    file.setPath(testfile1);
    file.open();
    file.setPassword("123456");
    file.load();
    CPPUNIT_ASSERT_EQUAL(""s, file.extendedHeader());
    CPPUNIT_ASSERT_EQUAL(""s, file.encryptedExtendedHeader());
    file.doBackup();
    file.extendedHeader() = "foo";
    file.save(PasswordFileSaveFlags::Encryption | PasswordFileSaveFlags::PasswordHashing);

    // resave testfile 2
    file.setPath(testfile2);
    file.open();
    file.load();
    CPPUNIT_ASSERT_EQUAL(""s, file.extendedHeader());
    CPPUNIT_ASSERT_EQUAL(""s, file.encryptedExtendedHeader());
    file.rootEntry()->setLabel("testfile2 - modified");
    new AccountEntry("newAccount", file.rootEntry());
    file.setPassword("654321");
    file.extendedHeader() = "foo";
    file.encryptedExtendedHeader() = "bar";
    file.doBackup();
    file.save(PasswordFileSaveFlags::Encryption | PasswordFileSaveFlags::PasswordHashing);

    // check results using the reading test
    testReading("extended writing", testfile1, "123456", testfile2, "654321", true, true);

    // check backup files
    testReading("extended writing", testfile1 + ".backup", "123456", testfile2 + ".backup", string(), false, false);
}
