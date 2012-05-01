#include <cppunit/TestFixture.h>
#include <cppunit/ui/text/TestRunner.h>

#include <cppunit/extensions/HelperMacros.h>

#include "util.h"
#include <cstring>

#ifdef CONFIGEXPAND_GUARDED
#define GUARD(S) (S + strlen(S) + 1)
#else
#define GUARD(S) "deadbeaf"
#endif

class ConfigTest: public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE( ConfigTest );
    CPPUNIT_TEST(test001);
    CPPUNIT_TEST(test002);
    CPPUNIT_TEST(test003);
    CPPUNIT_TEST(test005);
    CPPUNIT_TEST(test007);
    CPPUNIT_TEST(test008);
    CPPUNIT_TEST(test009);
    CPPUNIT_TEST(test010);
    CPPUNIT_TEST(test012);
    CPPUNIT_TEST(test013);
    CPPUNIT_TEST(test_load_all_configs);
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp() {
    };

    void tearDown() {
    }

    void test001() {
        config_t c = config_new();
        CPPUNIT_ASSERT(c != 0);
        CPPUNIT_ASSERT_EQUAL(0, config_load(c, "test_config.xml"));

        CPPUNIT_ASSERT_EQUAL((config_elem_t)0, config_get(c, "non.existing.key"));
        CPPUNIT_ASSERT_EQUAL((const char*)0, config_get_one(c, "non.existing.key", 0));

        CPPUNIT_ASSERT_EQUAL(std::string("qwerty"), std::string(config_get_one(c, "test_key", 0)));
        CPPUNIT_ASSERT_EQUAL((const char*)0, config_get_one(c, "test_key", 1));

        CPPUNIT_ASSERT_EQUAL(std::string("qwerty"), std::string(config_get_one_default(c, "test_key", 0, "not_this_value")));
        CPPUNIT_ASSERT_EQUAL(std::string("asdfg"), std::string(config_get_one_default(c, "non.existing.key", 0, "asdfg")));


        char *s = config_expand(c, "qwerty");
        CPPUNIT_ASSERT(s != 0);
        CPPUNIT_ASSERT_EQUAL(std::string("qwerty"), std::string(s));

        s = config_expand(c, "${wrong_var}asdfgh");
        CPPUNIT_ASSERT(s == 0);

        s = config_expand(c, "${test_key}asdfgh");
        CPPUNIT_ASSERT(s != 0);
        CPPUNIT_ASSERT_EQUAL(std::string("qwertyasdfgh"), std::string(s));
        CPPUNIT_ASSERT_EQUAL(std::string("deadbeaf"), std::string(GUARD(s)));

        s = config_expand(c, "qqq${test_key}asdfgh");
        CPPUNIT_ASSERT(s != 0);
        CPPUNIT_ASSERT_EQUAL(std::string("qqqqwertyasdfgh"), std::string(s));
        CPPUNIT_ASSERT_EQUAL(std::string("deadbeaf"), std::string(GUARD(s)));

        s = config_expand(c, "${test_key}qqq${test_key}asdfgh");
        CPPUNIT_ASSERT(s != 0);
        CPPUNIT_ASSERT_EQUAL(std::string("qwertyqqqqwertyasdfgh"), std::string(s));
        CPPUNIT_ASSERT_EQUAL(std::string("deadbeaf"), std::string(GUARD(s)));

        s = config_expand(c, "qqq${test_key}asdfgh${test_key}");
        CPPUNIT_ASSERT(s != 0);
        CPPUNIT_ASSERT_EQUAL(std::string("qqqqwertyasdfghqwerty"), std::string(s));
        CPPUNIT_ASSERT_EQUAL(std::string("deadbeaf"), std::string(GUARD(s)));

        s = config_expand(c, "qqq${test_key}asdfgh${invalid}");
        CPPUNIT_ASSERT(s == 0);

        CPPUNIT_ASSERT_EQUAL(std::string("asdfghqwertyzxcvbn"), std::string(config_get_one(c, "test_key_expanded", 0)));

//         CPPUNIT_ASSERT_EQUAL((const char*)0, config_get_one(c, "test_key_expanded_no_var", 0));
//         CPPUNIT_ASSERT_EQUAL((const char*)0, config_get_one(c, "use_defined_later", 0));
        CPPUNIT_ASSERT_EQUAL(std::string("asdfghqwertyzxcvbn"), std::string(config_get_one(c, "use_defined_above", 0)));

        CPPUNIT_ASSERT_EQUAL(std::string("1111234567222"), std::string(config_get_one(c, "another.test.value", 0)));

        s = config_expand(c, "qqq${test_key");
        CPPUNIT_ASSERT(s == 0);

        s = config_expand(c, "qqq${test_key_____${second}");
        CPPUNIT_ASSERT(s == 0);
        
        config_free(c);
    }

    void test002() {
        config_t c = config_new();
        CPPUNIT_ASSERT(c != 0);
        CPPUNIT_ASSERT_EQUAL(1, config_load(c, "no_file.xml"));
        config_free(c);
    }

    void test003() {
        config_t c = config_new();
        CPPUNIT_ASSERT(c != 0);
        CPPUNIT_ASSERT_EQUAL(0, config_load_with_id(c, "test_config.xml", "test_id"));
        CPPUNIT_ASSERT_EQUAL(std::string("test_id"), std::string(config_get_one(c, "id", 0)));
        CPPUNIT_ASSERT_EQUAL(std::string("value if id is test_id"), std::string(config_get_one(c, "value_with_id", 0)));
        CPPUNIT_ASSERT_EQUAL(std::string("1"), std::string(config_get_one(c, "simple_value", 0)));
        CPPUNIT_ASSERT_EQUAL(0, config_count(c, "does_not_exists"));
        CPPUNIT_ASSERT_EQUAL(1, config_count(c, "simple_value"));
        CPPUNIT_ASSERT_EQUAL(3, config_count(c, "multiple.val"));
        CPPUNIT_ASSERT_EQUAL(4, config_count(c, "multiple.simple"));
        CPPUNIT_ASSERT_EQUAL(std::string("val1"), std::string(config_get_attr(c, "simple_value_with_attr", 0, "attr1")));
        CPPUNIT_ASSERT_EQUAL(std::string("val2"), std::string(config_get_attr(c, "simple_value_with_attr", 0, "attr2")));
        CPPUNIT_ASSERT_EQUAL((char*)0, config_get_attr(c, "simple_value_with_attr", 100, "attr1"));
        CPPUNIT_ASSERT_EQUAL((char*)0, config_get_attr(c, "simple_value_with_attr", 1, "does_not_exists"));
        CPPUNIT_ASSERT_EQUAL((char*)0, config_get_attr(c, "simple_value_with_attr", 0, "does_not_exists"));
        config_free(c);
    }

    void test005() {
        config_t c = config_new();
        CPPUNIT_ASSERT(c != 0);
        CPPUNIT_ASSERT_EQUAL(1, config_load(c, "failed_to_load_002.xml"));
        config_free(c);
    }

    void test007() {
        config_t c = config_new();
        CPPUNIT_ASSERT(c != 0);
        CPPUNIT_ASSERT_EQUAL(0, config_load(c, "empty.xml"));
        config_free(c);
    }

    void test008() {
        config_t c = config_new();
        CPPUNIT_ASSERT(c != 0);
        CPPUNIT_ASSERT_EQUAL(1, config_load(c, "failed_to_load_003.xml"));
        config_free(c);
    }

    void test009() {
        config_t c = config_new();
        CPPUNIT_ASSERT(c != 0);
        CPPUNIT_ASSERT_EQUAL(0, config_load(c, "test_configs/test_config.xml"));
        config_free(c);
    }

    void test010() {
        config_t c = config_new();
        CPPUNIT_ASSERT(c != 0);
        CPPUNIT_ASSERT_EQUAL(1, config_load(c, "test_configs/failed_to_load_001.xml"));
        config_free(c);
    }

    void test012() {
        config_t c = config_new();
        CPPUNIT_ASSERT(c != 0);
        CPPUNIT_ASSERT_EQUAL(1, config_load(c, "test_configs/failed_to_load_003.xml"));
        config_free(c);
    }

    void test013() {
        config_t c = config_new();
        CPPUNIT_ASSERT(c != 0);
        CPPUNIT_ASSERT_EQUAL(1, config_load(c, "test_configs/failed_to_load_004.xml"));
        config_free(c);
    }

    void test_load_all_configs() {
        const char *generated_configs[] =	{
            "../../etc/s2s.xml.dist",
            "../../etc/sm.xml.dist",
            "../../etc/router.xml.dist",
            "../../etc/router-filter.xml.dist",
            "../../etc/templates/roster.xml.dist",
            "../../etc/c2s.xml.dist",
            "../../etc/router-users.xml.dist"
            };

        for (int i = 0; i < sizeof(generated_configs) / sizeof(generated_configs[0]); i++) 
        {
            std::stringstream msg;
            msg << "Faled to load config " << generated_configs[i];
            config_t c = config_new();
            CPPUNIT_ASSERT_MESSAGE(msg.str().c_str(), c != 0);
            CPPUNIT_ASSERT_EQUAL_MESSAGE(msg.str().c_str(), 0, config_load(c, generated_configs[i]));
            config_free(c);
        }
    }
};


CPPUNIT_TEST_SUITE_REGISTRATION( ConfigTest );

int main(int, char **)
{
    set_debug_flag(1);
    
    CppUnit::TextUi::TestRunner runner;
    CppUnit::TestFactoryRegistry &registry = CppUnit::TestFactoryRegistry::getRegistry();
    runner.addTest( registry.makeTest() );
    return runner.run() ? 0 : 1;
}
