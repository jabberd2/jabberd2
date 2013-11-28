#include <check.h>

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "util/util.h"

#ifdef CONFIGEXPAND_GUARDED
#define GUARD(S) (S + strlen(S) + 1)
#else
#define GUARD(S) "deadbeaf"
#endif

START_TEST (check_config_parse)
{
    config_t c = config_new();
    fail_unless (c != 0);

    int r = config_load_with_id(c, "test_config.xml", "test_id");
    ck_assert_int_eq (0, r); // Do not place config_load into ck_assert_xxxx  othewise it is called twice !!!

    ck_assert_str_eq ("test_id", config_get_one(c, "id", 0));
    ck_assert_str_eq ("value if id is test_id", config_get_one(c, "value_with_id", 0));
    ck_assert_str_eq ("1", config_get_one(c, "simple_value", 0));
    ck_assert_int_eq (0, config_count(c, "does_not_exists"));
    ck_assert_int_eq (1, config_count(c, "simple_value"));
    ck_assert_int_eq (3, config_count(c, "multiple.val"));
    ck_assert_int_eq (4, config_count(c, "multiple.simple"));
    ck_assert_str_eq ("val1", config_get_attr(c, "simple_value_with_attr", 0, "attr1"));
    ck_assert_str_eq ("val2", config_get_attr(c, "simple_value_with_attr", 0, "attr2"));
    fail_unless ((char*)0 == config_get_attr(c, "simple_value_with_attr", 100, "attr1"));
    fail_unless ((char*)0 == config_get_attr(c, "simple_value_with_attr", 1, "does_not_exists"));
    fail_unless ((char*)0 == config_get_attr(c, "simple_value_with_attr", 0, "does_not_exists"));
    config_free(c);
}
END_TEST

START_TEST (check_config_expand)
{
    config_t c = config_new();
    fail_unless (c != 0);
    int r = config_load(c, "test_config.xml");
    
    ck_assert_int_eq (0, r);

    ck_assert_ptr_eq ((config_elem_t)0, config_get(c, "non.existing.key"));
    fail_unless ((const char*)0 == config_get_one(c, "non.existing.key", 0));

    ck_assert_str_eq ("qwerty", config_get_one(c, "test_key", 0));
    fail_unless ((const char*)0 == config_get_one(c, "test_key", 1));

    ck_assert_str_eq ("qwerty", config_get_one_default(c, "test_key", 0, "not_this_value"));
    ck_assert_str_eq ("asdfg", config_get_one_default(c, "non.existing.key", 0, "asdfg"));


    char *s = config_expand(c, "qwerty");
    fail_unless (s != 0);
    ck_assert_str_eq ("qwerty", s);

    s = config_expand(c, "${wrong_var}asdfgh");
    fail_unless (s == 0);

    s = config_expand(c, "${test_key}asdfgh");
    fail_unless (s != 0);
    ck_assert_str_eq ("qwertyasdfgh", s);
    ck_assert_str_eq ("deadbeaf", GUARD(s));

    s = config_expand(c, "qqq${test_key}asdfgh");
    fail_unless (s != 0);
    ck_assert_str_eq ("qqqqwertyasdfgh", s);
    ck_assert_str_eq ("deadbeaf", GUARD(s));

    s = config_expand(c, "${test_key}qqq${test_key}asdfgh");
    fail_unless (s != 0);
    ck_assert_str_eq ("qwertyqqqqwertyasdfgh", s);
    ck_assert_str_eq ("deadbeaf", GUARD(s));

    s = config_expand(c, "qqq${test_key}asdfgh${test_key}");
    fail_unless (s != 0);
    ck_assert_str_eq ("qqqqwertyasdfghqwerty", s);
    ck_assert_str_eq ("deadbeaf", GUARD(s));

    s = config_expand(c, "qqq${test_key}asdfgh${invalid}");
    fail_unless (s == 0);

    ck_assert_str_eq ("asdfghqwertyzxcvbn", config_get_one(c, "test_key_expanded", 0));

//    ck_assert_str_eq ((const char*)0, config_get_one(c, "test_key_expanded_no_var", 0));
//    ck_assert_str_eq ((const char*)0, config_get_one(c, "use_defined_later", 0));
    ck_assert_str_eq ("asdfghqwertyzxcvbn", config_get_one(c, "use_defined_above", 0));

    ck_assert_str_eq ("1111234567222", config_get_one(c, "another.test.value", 0));

    s = config_expand(c, "qqq${test_key");
    fail_unless (s == 0);

    s = config_expand(c, "qqq${test_key_____${second}");
    fail_unless (s == 0);

    config_free(c);
}
END_TEST

START_TEST (check_config_missing)
{
    config_t c = config_new();
    fail_unless (c != 0);
    int load_result = config_load(c, "no_file.xml");
    ck_assert_int_eq (1, load_result);
    config_free(c);
}
END_TEST

START_TEST (check_config_empty)
{
    config_t c = config_new();
    fail_unless (c != 0);
    int r = config_load(c, "empty.xml");
    ck_assert_int_eq (0, r);
    config_free(c);
}
END_TEST

START_TEST (check_config_include)
{
    config_t c = config_new();
    fail_unless (c != 0);
    int r = config_load(c, "test_include.xml");
    ck_assert_int_eq (0, r);
    config_free(c);
}
END_TEST

START_TEST (check_config_fail_002)
{
    config_t c = config_new();
    fail_unless (c != 0);
    int r = config_load(c, "failed_to_load_002.xml");
    ck_assert_int_eq (1, r);
    config_free(c);
}
END_TEST

START_TEST (check_config_fail_003)
{
    config_t c = config_new();
    fail_unless (c != 0);
    int r = config_load(c, "failed_to_load_003.xml");
    ck_assert_int_eq (1, r);
    config_free(c);
}
END_TEST

START_TEST (check_config_fail_004)
{
    config_t c = config_new();
    fail_unless (c != 0);
    int r = config_load(c, "failed_to_load_004.xml");
    ck_assert_int_eq (1, r);
    config_free(c);
}
END_TEST

const char *generated_configs[] = {
    "../etc/s2s.xml.dist",
    "../etc/sm.xml.dist",
    "../etc/router.xml.dist",
    "../etc/router-filter.xml.dist",
    "../etc/templates/roster.xml.dist",
    "../etc/c2s.xml.dist",
    "../etc/router-users.xml.dist"
};

START_TEST (test_generated_config)
{
    char msg[1000];
    snprintf(msg, 1000, "Faled to load config %d: %s", _i, generated_configs[_i]);
    config_t c = config_new();
    fail_unless (c != 0, msg);
    fail_unless (0 == config_load(c, generated_configs[_i]), msg);
    config_free(c);
}
END_TEST


Suite* config_test_suite (void)
{
    Suite *s = suite_create ("XML configuration");

    TCase *tc_def = tcase_create ("Default generated configs");
    tcase_add_loop_test (tc_def, test_generated_config, 0, sizeof(generated_configs) / sizeof(generated_configs[0]));
    suite_add_tcase (s, tc_def);

    TCase *tc_parsing = tcase_create ("Parsing");
    tcase_add_test (tc_parsing, check_config_parse);
    tcase_add_test (tc_parsing, check_config_expand);
    tcase_add_test (tc_parsing, check_config_missing);
    tcase_add_test (tc_parsing, check_config_empty);
    tcase_add_test (tc_parsing, check_config_include);
    tcase_add_test (tc_parsing, check_config_fail_002);
    tcase_add_test (tc_parsing, check_config_fail_003);
    tcase_add_test (tc_parsing, check_config_fail_004);
    suite_add_tcase (s, tc_parsing);

    return s;
}

int main (void)
{
//     set_debug_flag(1);

    int number_failed;
    Suite *s = config_test_suite ();
    SRunner *sr = srunner_create (s);
    srunner_run_all (sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
