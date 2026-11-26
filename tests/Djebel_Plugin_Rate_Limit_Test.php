<?php

use PHPUnit\Framework\TestCase;

/**
 * Tests for the Djebel_Plugin_Rate_Limit class: the smart defaults its ini ships, the rules
 * filter, and the counters it keeps in djebel's cache.
 */
class Djebel_Plugin_Rate_Limit_Test extends TestCase
{
    // The start of a window, so no test straddles a window's end.
    const NOW = 1795442400;

    // The window and the subnet multiplier the defaults section of the shipped ini sets.
    const DEFAULT_WINDOW_SECONDS = 3600;
    const DEFAULT_SUBNET_MAX_REQUESTS_MULTIPLIER = 8;

    protected function tearDown(): void
    {
        $cache_params = [ 'plugin' => Djebel_Plugin_Rate_Limit::CACHE_PLUGIN, ];
        $is_cleared = Dj_App_Cache::removeAll($cache_params);

        $this->assertTrue($is_cleared, 'the counters were cleared');
    }

    /**
     * The listener the counting tests register: an exact users/auth rule that counts failures only,
     * with a budget of two.
     * @param array $rules
     * @param array $ctx
     * @return array
     */
    public function filterRulesAddExactAuth($rules, $ctx = [])
    {
        $new_rules = $rules;
        $new_rules['users_auth'] = [ 'pattern' => 'users/auth', 'max_requests' => 2, 'count_successes' => 0, 'over_limit_fake_success' => 1, ];

        return $new_rules;
    }

    /**
     * The listener that switches the reads rule off.
     * @param array $rules
     * @param array $ctx
     * @return array
     */
    public function filterRulesSwitchReadsOff($rules, $ctx = [])
    {
        $new_rules = $rules;
        $new_rules['reads']['max_requests'] = 0;

        return $new_rules;
    }

    /**
     * The listener that adds a rule with only a pattern and a budget, the way an app adds one.
     * @param array $rules
     * @param array $ctx
     * @return array
     */
    public function filterRulesAddBareRule($rules, $ctx = [])
    {
        $new_rules = $rules;
        $new_rules['web_send'] = [ 'pattern' => 'web/send', 'max_requests' => 10, ];

        return $new_rules;
    }

    /**
     * The listener that adds rules the way a careless app might write them: values as strings, a
     * window that cannot roll, one rule with no pattern and one with no budget.
     * @param array $rules
     * @param array $ctx
     * @return array
     */
    public function filterRulesAddLooselySpelled($rules, $ctx = [])
    {
        $new_rules = $rules;
        $new_rules['loose'] = [ 'pattern' => 'reports/export', 'max_requests' => '5', 'over_limit_fake_success' => 'yes', 'count_successes' => 'off', ];
        $new_rules['bad_window'] = [ 'pattern' => 'reports/import', 'max_requests' => 5, 'window_seconds' => '-1', ];
        $new_rules['no_pattern'] = [ 'max_requests' => 5, ];
        $new_rules['no_budget'] = [ 'pattern' => 'reports/*', ];

        return $new_rules;
    }

    /**
     * Records two failed requests, the budget the exact users/auth rule allows.
     * @param array $params
     * @return array the two count results
     */
    public function countTwoFailures($params)
    {
        $rate_limit_obj = Djebel_Plugin_Rate_Limit::getInstance();
        $fail_params = $params;
        $fail_params['is_success'] = false;

        $first_res_obj = $rate_limit_obj->count($fail_params);
        $second_res_obj = $rate_limit_obj->count($fail_params);
        $count_results = [ $first_res_obj, $second_res_obj, ];

        return $count_results;
    }

    /**
     * Pins the smart defaults the ini ships: what an action does decides its rule, and no product's
     * route has one of its own, so a send and a users/delete take the generic rules.
     */
    public function testFindRuleUsesTheSmartDefaults()
    {
        $rate_limit_obj = Djebel_Plugin_Rate_Limit::getInstance();

        $auth_rule = $rate_limit_obj->findRule('users/auth');
        $this->assertSame('sign_in', $auth_rule['name']);

        $secret_rule = $rate_limit_obj->findRule('users/resetpasswordcode');
        $this->assertSame('account_secrets', $secret_rule['name']);

        $lookup_rule = $rate_limit_obj->findRule('users/check');
        $this->assertSame('lookups', $lookup_rule['name']);

        $write_rule = $rate_limit_obj->findRule('chats/delete');
        $this->assertSame('writes', $write_rule['name']);

        $user_delete_rule = $rate_limit_obj->findRule('users/delete');
        $this->assertSame('writes', $user_delete_rule['name']);

        $read_rule = $rate_limit_obj->findRule('vehicles/list');
        $this->assertSame('reads', $read_rule['name']);

        $send_rule = $rate_limit_obj->findRule('web/send');
        $this->assertSame('any', $send_rule['name']);

        $other_rule = $rate_limit_obj->findRule('pub/something');
        $this->assertSame('any', $other_rule['name']);
    }

    /**
     * Pins a sub-module named like a write keeping its action's rule: the one slash sits before the
     * action, so users.addaddresses/list is a read.
     */
    public function testFindRuleKeepsTheActionsRuleUnderASubModule()
    {
        $rate_limit_obj = Djebel_Plugin_Rate_Limit::getInstance();
        $route_params = [ 'module' => 'users', 'sub_module' => 'add_addresses', 'action' => 'list', ];

        $route = $rate_limit_obj->buildRoute($route_params);
        $this->assertSame('users.addaddresses/list', $route);

        $rule = $rate_limit_obj->findRule($route);
        $this->assertSame('reads', $rule['name']);
    }

    /**
     * Pins case, underscores and dashes being ignored, so one action spelled three ways is one route
     * and spends one budget.
     */
    public function testBuildRouteIgnoresCaseUnderscoresDashes()
    {
        $rate_limit_obj = Djebel_Plugin_Rate_Limit::getInstance();

        $camel_params = [ 'module' => 'Users', 'action' => 'resetPassword', ];
        $camel_route = $rate_limit_obj->buildRoute($camel_params);
        $this->assertSame('users/resetpassword', $camel_route);

        $snake_params = [ 'module' => 'users', 'action' => 'reset_password', ];
        $snake_route = $rate_limit_obj->buildRoute($snake_params);
        $this->assertSame($camel_route, $snake_route);

        $dash_params = [ 'module' => 'users', 'action' => 'reset-password', ];
        $dash_route = $rate_limit_obj->buildRoute($dash_params);
        $this->assertSame($camel_route, $dash_route);
    }

    /**
     * Pins getRules() handing a rule back ready to use: the ini's strings become ints and booleans,
     * the defaults section fills what the rule leaves out, and a value the rule sets beats the
     * default (sign_in counts no successes, while the defaults count them).
     */
    public function testGetRulesHandsTheDefaultsBackTyped()
    {
        $rate_limit_obj = Djebel_Plugin_Rate_Limit::getInstance();
        $rules = $rate_limit_obj->getRules();

        $expected_sign_in = [
            'pattern' => '*/auth|*/login',
            'max_requests' => 20,
            'window_seconds' => self::DEFAULT_WINDOW_SECONDS,
            'subnet_max_requests_multiplier' => self::DEFAULT_SUBNET_MAX_REQUESTS_MULTIPLIER,
            'count_successes' => false,
            'over_limit_fake_success' => true,
        ];

        $this->assertSame($expected_sign_in, $rules['sign_in']);
        $this->assertTrue($rules['reads']['count_successes'], 'a rule that sets nothing takes the default');
        $this->assertSame([ 'sign_in', 'account_secrets', 'lookups', 'writes', 'reads', 'any', ], array_keys($rules));
    }

    /**
     * Pins the fallback for an unreadable file holding exactly the shipped defaults section, so the
     * app's own rules limit the same way with or without the file.
     */
    public function testFallbackDefaultsMatchTheShippedFile()
    {
        $plugin_dir = dirname(__DIR__);
        $rules_file = $plugin_dir . '/' . Djebel_Plugin_Rate_Limit::DEFAULT_RULES_FILE;
        $parsed_sections = parse_ini_file($rules_file, true, INI_SCANNER_RAW);

        $this->assertNotEmpty($parsed_sections, 'the shipped defaults file parses');
        $this->assertEquals($parsed_sections[Djebel_Plugin_Rate_Limit::DEFAULTS_SECTION], Djebel_Plugin_Rate_Limit::FALLBACK_DEFAULTS);
    }

    /**
     * Pins a site's own rules coming from its options, in the defaults file's layout: a new rule is
     * added, a shipped rule changes only the field it sets, a max_requests of 0 switches one off,
     * and the site's defaults reach every rule. The options are put back afterwards.
     */
    public function testGetRulesTakesTheSitesRulesFromItsOptions()
    {
        $rate_limit_obj = Djebel_Plugin_Rate_Limit::getInstance();
        $options_obj = Dj_App_Options::getInstance();
        $original_options = $options_obj->load();

        // The shape djebel's parser makes of [plugins.djebel-plugin-rate-limit.*] sections.
        $site_options = [
            'plugins' => [
                'djebel_plugin_rate_limit' => [
                    'defaults' => [ 'window_seconds' => '600', ],
                    'rules' => [
                        'users_delete' => [ 'pattern' => 'users/delete', 'max_requests' => '10', 'count_successes' => '0', ],
                        'sign_in' => [ 'max_requests' => '5', ],
                        'reads' => [ 'max_requests' => '0', ],
                    ],
                ],
            ],
        ];

        try {
            $options_obj->setData($site_options);
            $rules = $rate_limit_obj->getRules();
        } finally {
            $options_obj->setData($original_options);
        }

        $this->assertSame('users/delete', $rules['users_delete']['pattern']);
        $this->assertSame(10, $rules['users_delete']['max_requests']);
        $this->assertSame(600, $rules['users_delete']['window_seconds']);
        $this->assertFalse($rules['users_delete']['count_successes']);

        $this->assertSame(5, $rules['sign_in']['max_requests']);
        $this->assertSame('*/auth|*/login', $rules['sign_in']['pattern']);
        $this->assertTrue($rules['sign_in']['over_limit_fake_success']);

        $this->assertArrayNotHasKey('reads', $rules);
        $this->assertSame(600, $rules['lookups']['window_seconds']);
    }

    /**
     * Pins an app's rule needing only a pattern and a budget: everything else comes from the
     * defaults section.
     */
    public function testGetRulesFillsAListenersRuleFromTheDefaults()
    {
        $rate_limit_obj = Djebel_Plugin_Rate_Limit::getInstance();
        Dj_App_Hooks::addFilter(Djebel_Plugin_Rate_Limit::FILTER_RULES, [ $this, 'filterRulesAddBareRule' ]);

        try {
            $rules = $rate_limit_obj->getRules();
        } finally {
            $is_removed = Dj_App_Hooks::removeFilter(Djebel_Plugin_Rate_Limit::FILTER_RULES, [ $this, 'filterRulesAddBareRule' ]);
        }

        $expected_web_send = [
            'pattern' => 'web/send',
            'max_requests' => 10,
            'window_seconds' => self::DEFAULT_WINDOW_SECONDS,
            'subnet_max_requests_multiplier' => self::DEFAULT_SUBNET_MAX_REQUESTS_MULTIPLIER,
            'count_successes' => true,
            'over_limit_fake_success' => false,
        ];

        $this->assertSame($expected_web_send, $rules['web_send']);
        $this->assertTrue($is_removed, 'the test listener came off');
    }

    /**
     * Pins a listener's rule getting the same treatment as the file's: strings are typed, and a rule
     * with a window that could not roll, no pattern or no budget is left out instead of matching
     * everything or nothing.
     */
    public function testGetRulesTypesAListenersRule()
    {
        $rate_limit_obj = Djebel_Plugin_Rate_Limit::getInstance();
        Dj_App_Hooks::addFilter(Djebel_Plugin_Rate_Limit::FILTER_RULES, [ $this, 'filterRulesAddLooselySpelled' ]);

        try {
            $rules = $rate_limit_obj->getRules();
        } finally {
            $is_removed = Dj_App_Hooks::removeFilter(Djebel_Plugin_Rate_Limit::FILTER_RULES, [ $this, 'filterRulesAddLooselySpelled' ]);
        }

        $expected_loose = [
            'pattern' => 'reports/export',
            'max_requests' => 5,
            'window_seconds' => self::DEFAULT_WINDOW_SECONDS,
            'subnet_max_requests_multiplier' => self::DEFAULT_SUBNET_MAX_REQUESTS_MULTIPLIER,
            'count_successes' => false,
            'over_limit_fake_success' => true,
        ];

        $this->assertSame($expected_loose, $rules['loose']);
        $this->assertArrayNotHasKey('bad_window', $rules);
        $this->assertArrayNotHasKey('no_pattern', $rules);
        $this->assertArrayNotHasKey('no_budget', $rules);
        $this->assertTrue($is_removed, 'the test listener came off');
    }

    /**
     * Pins a listener switching a rule off with a max_requests of 0: the routes it covered fall to
     * the next rule that matches.
     */
    public function testFindRuleSkipsARuleSwitchedOff()
    {
        $rate_limit_obj = Djebel_Plugin_Rate_Limit::getInstance();
        Dj_App_Hooks::addFilter(Djebel_Plugin_Rate_Limit::FILTER_RULES, [ $this, 'filterRulesSwitchReadsOff' ]);

        try {
            $rule = $rate_limit_obj->findRule('vehicles/list');
        } finally {
            $is_removed = Dj_App_Hooks::removeFilter(Djebel_Plugin_Rate_Limit::FILTER_RULES, [ $this, 'filterRulesSwitchReadsOff' ]);
        }

        $this->assertSame('any', $rule['name']);
        $this->assertTrue($is_removed, 'the test listener came off');
    }

    /**
     * Pins an exact rule winning over every wildcard rule that also matches the route.
     */
    public function testFindRulePrefersAnExactRule()
    {
        $rate_limit_obj = Djebel_Plugin_Rate_Limit::getInstance();
        Dj_App_Hooks::addFilter(Djebel_Plugin_Rate_Limit::FILTER_RULES, [ $this, 'filterRulesAddExactAuth' ]);

        try {
            $rule = $rate_limit_obj->findRule('users/auth');
        } finally {
            $is_removed = Dj_App_Hooks::removeFilter(Djebel_Plugin_Rate_Limit::FILTER_RULES, [ $this, 'filterRulesAddExactAuth' ]);
        }

        $this->assertSame('users_auth', $rule['name']);
        $this->assertSame(2, $rule['max_requests']);
        $this->assertTrue($is_removed, 'the test listener came off');
    }

    /**
     * Pins the budget closing on the caller's IP once its failures reach it, and only then.
     */
    public function testCheckIsOverOnceFailuresReachTheBudget()
    {
        $rate_limit_obj = Djebel_Plugin_Rate_Limit::getInstance();
        $auth_params = [ 'module' => 'users', 'action' => 'auth', 'ip' => '203.0.113.7', 'now' => self::NOW, ];
        Dj_App_Hooks::addFilter(Djebel_Plugin_Rate_Limit::FILTER_RULES, [ $this, 'filterRulesAddExactAuth' ]);

        try {
            $fresh_res_obj = $rate_limit_obj->check($auth_params);
            $count_results = $this->countTwoFailures($auth_params);
            $over_res_obj = $rate_limit_obj->check($auth_params);
        } finally {
            $is_removed = Dj_App_Hooks::removeFilter(Djebel_Plugin_Rate_Limit::FILTER_RULES, [ $this, 'filterRulesAddExactAuth' ]);
        }

        $this->assertTrue($fresh_res_obj->isSuccess());
        $this->assertFalse($fresh_res_obj->over_limit);
        $this->assertTrue($count_results[0]->counted);
        $this->assertTrue($count_results[1]->isSuccess());
        $this->assertTrue($over_res_obj->over_limit);
        $this->assertSame('ip', $over_res_obj->over_key);
        $this->assertSame('users_auth', $over_res_obj->rule['name']);
        $this->assertTrue($is_removed, 'the test listener came off');
    }

    /**
     * Pins a neighbour in the same /24 staying under: the subnet's budget is eight times the IP's,
     * so one noisy address does not lock out its network.
     */
    public function testCheckKeepsANeighbourInTheSubnetUnder()
    {
        $rate_limit_obj = Djebel_Plugin_Rate_Limit::getInstance();
        $auth_params = [ 'module' => 'users', 'action' => 'auth', 'ip' => '203.0.113.7', 'now' => self::NOW, ];
        $neighbour_params = $auth_params;
        $neighbour_params['ip'] = '203.0.113.99';
        Dj_App_Hooks::addFilter(Djebel_Plugin_Rate_Limit::FILTER_RULES, [ $this, 'filterRulesAddExactAuth' ]);

        try {
            $count_results = $this->countTwoFailures($auth_params);
            $neighbour_res_obj = $rate_limit_obj->check($neighbour_params);
        } finally {
            $is_removed = Dj_App_Hooks::removeFilter(Djebel_Plugin_Rate_Limit::FILTER_RULES, [ $this, 'filterRulesAddExactAuth' ]);
        }

        $this->assertTrue($count_results[1]->isSuccess());
        $this->assertFalse($neighbour_res_obj->over_limit);
        $this->assertTrue($is_removed, 'the test listener came off');
    }

    /**
     * Pins each window counting from nothing: the window's number is part of the counter's name.
     */
    public function testCheckStartsEachWindowFresh()
    {
        $rate_limit_obj = Djebel_Plugin_Rate_Limit::getInstance();
        $auth_params = [ 'module' => 'users', 'action' => 'auth', 'ip' => '203.0.113.7', 'now' => self::NOW, ];
        $next_window_params = $auth_params;
        $next_window_params['now'] = self::NOW + self::DEFAULT_WINDOW_SECONDS;
        Dj_App_Hooks::addFilter(Djebel_Plugin_Rate_Limit::FILTER_RULES, [ $this, 'filterRulesAddExactAuth' ]);

        try {
            $count_results = $this->countTwoFailures($auth_params);
            $next_window_res_obj = $rate_limit_obj->check($next_window_params);
        } finally {
            $is_removed = Dj_App_Hooks::removeFilter(Djebel_Plugin_Rate_Limit::FILTER_RULES, [ $this, 'filterRulesAddExactAuth' ]);
        }

        $this->assertTrue($count_results[1]->isSuccess());
        $this->assertFalse($next_window_res_obj->over_limit);
        $this->assertTrue($is_removed, 'the test listener came off');
    }

    /**
     * Pins a signed-in user's own counter: it closes for the user even with no IP given, so moving
     * between addresses does not reset an account's budget.
     */
    public function testCheckCountsASignedInUserOnItsOwn()
    {
        $rate_limit_obj = Djebel_Plugin_Rate_Limit::getInstance();
        $user_params = [ 'module' => 'users', 'action' => 'auth', 'user_id' => 42, 'now' => self::NOW, ];
        Dj_App_Hooks::addFilter(Djebel_Plugin_Rate_Limit::FILTER_RULES, [ $this, 'filterRulesAddExactAuth' ]);

        try {
            $count_results = $this->countTwoFailures($user_params);
            $over_res_obj = $rate_limit_obj->check($user_params);
        } finally {
            $is_removed = Dj_App_Hooks::removeFilter(Djebel_Plugin_Rate_Limit::FILTER_RULES, [ $this, 'filterRulesAddExactAuth' ]);
        }

        $this->assertTrue($count_results[1]->isSuccess());
        $this->assertTrue($over_res_obj->over_limit);
        $this->assertSame('user', $over_res_obj->over_key);
        $this->assertTrue($is_removed, 'the test listener came off');
    }

    /**
     * Pins a success on a failures-only rule spending nothing, so a person who signs in right is
     * never limited.
     */
    public function testCountSkipsASuccessOnAFailuresOnlyRule()
    {
        $rate_limit_obj = Djebel_Plugin_Rate_Limit::getInstance();
        $success_params = [ 'module' => 'users', 'action' => 'auth', 'ip' => '198.51.100.5', 'now' => self::NOW, 'is_success' => true, ];

        $count_res_obj = $rate_limit_obj->count($success_params);

        $this->assertTrue($count_res_obj->isSuccess());
        $this->assertFalse($count_res_obj->counted);
    }

    /**
     * Pins a counted request landing in the cache under the key buildCounterKeys() names, one hit
     * per request, and the subnet's budget being the rule's multiplier times the IP's.
     */
    public function testCountStoresOneHitPerRequest()
    {
        $rate_limit_obj = Djebel_Plugin_Rate_Limit::getInstance();
        $list_params = [ 'module' => 'vehicles', 'action' => 'list', 'ip' => '198.51.100.6', 'now' => self::NOW, 'is_success' => true, ];

        $count_res_obj = $rate_limit_obj->count($list_params);
        $this->assertTrue($count_res_obj->counted);

        $key_params = $list_params;
        $key_params['rule'] = $rate_limit_obj->findRule('vehicles/list');
        $counter_keys = $rate_limit_obj->buildCounterKeys($key_params);
        $cache_params = [ 'plugin' => Djebel_Plugin_Rate_Limit::CACHE_PLUGIN, ];

        $stored_count = Dj_App_Cache::get($counter_keys['ip']['key'], $cache_params);
        $this->assertEquals(1, $stored_count);
        $this->assertSame(2400 * self::DEFAULT_SUBNET_MAX_REQUESTS_MULTIPLIER, $counter_keys['subnet']['max_requests']);
    }

    /**
     * Pins a request that names no route failing with its code, for check() and count() alike.
     */
    public function testCheckWithoutARouteFailsWithItsCode()
    {
        $rate_limit_obj = Djebel_Plugin_Rate_Limit::getInstance();
        $no_action_params = [ 'module' => 'users', 'ip' => '203.0.113.7', ];

        $check_res_obj = $rate_limit_obj->check($no_action_params);
        $this->assertTrue($check_res_obj->isError());
        $this->assertSame(Djebel_Plugin_Rate_Limit::CODE_NO_ROUTE, $check_res_obj->code);

        $count_res_obj = $rate_limit_obj->count($no_action_params);
        $this->assertTrue($count_res_obj->isError());
        $this->assertSame(Djebel_Plugin_Rate_Limit::CODE_NO_ROUTE, $count_res_obj->code);
    }

    /**
     * Pins buildCounterKeys() naming no counter without a rule, rather than counting under an empty
     * one.
     */
    public function testBuildCounterKeysWithoutARuleIsEmpty()
    {
        $rate_limit_obj = Djebel_Plugin_Rate_Limit::getInstance();
        $key_params = [ 'ip' => '203.0.113.7', 'now' => self::NOW, ];

        $counter_keys = $rate_limit_obj->buildCounterKeys($key_params);

        $this->assertEmpty($counter_keys);
    }

    /**
     * Pins the subnet a caller shares a budget with: a /24 for IPv4, a /64 for IPv6, and an address
     * that does not parse as its own key.
     */
    public function testGetSubnetKeyGroupsAddressesByNetwork()
    {
        $rate_limit_obj = Djebel_Plugin_Rate_Limit::getInstance();

        $v4_key = $rate_limit_obj->getSubnetKey('203.0.113.7');
        $this->assertSame('cb0071', $v4_key);

        $v4_other_net_key = $rate_limit_obj->getSubnetKey('203.0.114.7');
        $this->assertNotSame($v4_key, $v4_other_net_key);

        $v6_key = $rate_limit_obj->getSubnetKey('2001:db8:abcd:12::1');
        $v6_same_net_key = $rate_limit_obj->getSubnetKey('2001:db8:abcd:12:ffff::9');
        $this->assertSame($v6_key, $v6_same_net_key);

        $bad_key = $rate_limit_obj->getSubnetKey('not-an-ip');
        $this->assertSame('not-an-ip', $bad_key);
    }
}
