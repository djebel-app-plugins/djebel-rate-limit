<?php
/*
plugin_name: Djebel Rate Limit
plugin_uri: https://djebel.com/plugins/djebel-rate-limit
description: Request budgets per route (Djebel_Plugin_Rate_Limit): route patterns with smart defaults by kind of action, read from default_rules.ini, one filter that adds or replaces a rule, and counters per IP, subnet and signed-in user, kept in djebel's cache, which counts in APCu where the server has it and in files otherwise.
version: 1.0.0
load_priority: 20
tags: rate limit, security
stable_version: 1.0.0
min_php_ver: 7.4
min_dj_app_ver: 1.0.0
tested_with_dj_app_ver: 1.0.0
author_name: Svetoslav Marinov (Slavi)
company_name: Orbisius
author_uri: https://orbisius.com
text_domain: djebel-plugin-rate-limit
license: gpl2
*/

// The caller asks before a route runs and tells it after:
//   $rate_limit_obj = Djebel_Plugin_Rate_Limit::getInstance();
//   $check_res_obj = $rate_limit_obj->check($req_params);   // over_limit, over_key, rule
//   $count_res_obj = $rate_limit_obj->count($req_params);   // after the response, with is_success
// $req_params: module, sub_module (optional), action, ip, user_id (optional), is_success (count).
// A pre-defined / custom implementation wins: if the class already exists, don't redeclare.
if (class_exists('Djebel_Plugin_Rate_Limit')) {
    return;
}

/**
 * Request budgets per route. A route is <module>[.<sub_module>]/<action>, matched with case,
 * '_' and '-' ignored on both sides, so 'reset_password' and 'resetPassword' are one route.
 */
class Djebel_Plugin_Rate_Limit
{
    const FILTER_RULES = 'app.plugin.rate_limit.filter.rules';

    // The cache dir the counters live in, so removeAll() on it clears every counter and nothing
    // else.
    const CACHE_PLUGIN = 'djebel-rate-limit';

    // The smart defaults, beside this file: one defaults section every rule starts from, and one
    // section per rule, its name after the prefix. The site's options hold the same sections,
    // under OPTIONS_KEY.
    const DEFAULT_RULES_FILE = 'default_rules.ini';
    const OPTIONS_KEY = 'plugins.djebel-plugin-rate-limit';
    const DEFAULTS_SECTION = self::OPTIONS_KEY . '.defaults';
    const RULES_SECTION = self::OPTIONS_KEY . '.rules';
    const RULES_SECTION_PREFIX = self::RULES_SECTION . '.';

    // The file's defaults section, used only when the file cannot be read, so the rules an app adds
    // through the filter still limit. A test keeps the two equal.
    const FALLBACK_DEFAULTS = [
        'window_seconds' => 3600,
        'subnet_max_requests_multiplier' => 8,
        'count_successes' => 1,
        'over_limit_fake_success' => 0,
    ];

    const CODE_NO_ROUTE = 'app.plugin.rate_limit.no_route';
    const CODE_COUNT_FAILED = 'app.plugin.rate_limit.count_failed';
    const CODE_RULES_UNREADABLE = 'app.plugin.rate_limit.rules_unreadable';

    // Both prefixes are whole bytes (24 / 8 = 3, 64 / 8 = 8), so a subnet key keeps leading bytes
    // with no masking. IPv6 rotation inside a /64 costs nothing, so the /64 is the person.
    const CIDR_V4_BITS = 24;
    const CIDR_V6_BITS = 64;

    const TIER_EXACT = 1;
    const TIER_PREFIX = 2;
    const TIER_SUFFIX = 3;
    const TIER_ANY = 4;

    public static function getInstance()
    {
        static $instance = null;

        if (is_null($instance)) {
            $instance = new static();
        }

        return $instance;
    }

    /**
     * Whether a request may run: reads the caller's counters for the route's rule, and adds
     * nothing. Over is a count that has reached the budget, since the counters hold the hits
     * already made.
     * @param array $params module, sub_module, action, ip, user_id, now
     * @return Dj_App_Result over_limit, over_key (ip, subnet, user or ''), rule (with its name)
     */
    public function check($params = [])
    {
        $res_obj = new Dj_App_Result();
        $res_obj->over_limit = false;
        $res_obj->over_key = '';
        $res_obj->rule = [];

        $route = $this->buildRoute($params);

        if (empty($route)) {
            $res_obj->msg('A route needs a module and an action');
            $res_obj->code(Djebel_Plugin_Rate_Limit::CODE_NO_ROUTE);

            return $res_obj;
        }

        $rule = $this->findRule($route);
        $res_obj->rule = $rule;
        $res_obj->status(true);

        if (empty($rule)) {
            return $res_obj;
        }

        $key_params = $params;
        $key_params['rule'] = $rule;

        $counter_keys = $this->buildCounterKeys($key_params);
        $cache_params = [ 'plugin' => Djebel_Plugin_Rate_Limit::CACHE_PLUGIN, ];

        foreach ($counter_keys as $key_type => $counter_rec) {
            $stored_count = Dj_App_Cache::get($counter_rec['key'], $cache_params);
            $count = (int) $stored_count;

            if ($count >= $counter_rec['max_requests']) {
                $res_obj->over_limit = true;
                $res_obj->over_key = $key_type;

                break;
            }
        }

        return $res_obj;
    }

    /**
     * Records one request against the caller's counters. A success counts only where the rule
     * sets count_successes, so a person who gets it right is never limited on a guarded route.
     * Counting is best effort: a store that fails is logged and never fails the request.
     * @param array $params module, sub_module, action, ip, user_id, is_success, now
     * @return Dj_App_Result counted (whether anything was recorded); status false when a
     *                       counter could not be written
     */
    public function count($params = [])
    {
        $res_obj = new Dj_App_Result();
        $res_obj->counted = false;

        $route = $this->buildRoute($params);

        if (empty($route)) {
            $res_obj->msg('A route needs a module and an action');
            $res_obj->code(Djebel_Plugin_Rate_Limit::CODE_NO_ROUTE);

            return $res_obj;
        }

        $rule = $this->findRule($route);
        $res_obj->status(true);

        if (empty($rule)) {
            return $res_obj;
        }

        $is_success = !empty($params['is_success']);

        if ($is_success && empty($rule['count_successes'])) {
            return $res_obj;
        }

        $key_params = $params;
        $key_params['rule'] = $rule;

        $counter_keys = $this->buildCounterKeys($key_params);

        foreach ($counter_keys as $key_type => $counter_rec) {
            $inc_params = [
                'plugin' => Djebel_Plugin_Rate_Limit::CACHE_PLUGIN,
                'ttl' => $counter_rec['ttl'],
            ];

            $inc_res_obj = Dj_App_Cache::increment($counter_rec['key'], $inc_params);

            if ($inc_res_obj->isError()) {
                $log_data = [ 'code' => $inc_res_obj->code, 'key_type' => $key_type, 'msg' => $inc_res_obj->msg, ];

                Dj_App_Log::error($log_data, __METHOD__);
                $res_obj->status(false);
                $res_obj->code(Djebel_Plugin_Rate_Limit::CODE_COUNT_FAILED);
            }
        }

        $res_obj->counted = true;

        return $res_obj;
    }

    /**
     * Every rule, ready to match: the rules from DEFAULT_RULES_FILE, changed or added by the site's
     * options in the same layout, then by the rules filter, each merged over the defaults (the
     * file's, overridden by the site's), so a rule sets only what differs. Each comes back with int max_requests, window_seconds and
     * subnet_max_requests_multiplier, and boolean count_successes and over_limit_fake_success,
     * however the file or a listener spelled them. A rule without a pattern or a budget limits
     * nothing and is left out, so a listener switches a rule off with a max_requests of 0; one
     * left without a positive window or multiplier is left out too.
     * A defaults file that cannot be read, or holds nothing, is logged; FALLBACK_DEFAULTS then
     * stands in for its defaults section, and the filter's rules are all that is left.
     * @param array $ctx route
     * @return array rule name => pattern, max_requests, window_seconds,
     *               subnet_max_requests_multiplier, count_successes, over_limit_fake_success
     */
    public function getRules($ctx = [])
    {
        $rules_file = __DIR__ . '/' . Djebel_Plugin_Rate_Limit::DEFAULT_RULES_FILE;

        // RAW hands every value back as written, so a pattern's '|' and '*' are never read as
        // INI operators.
        $parsed_sections = parse_ini_file($rules_file, true, INI_SCANNER_RAW);

        if (empty($parsed_sections)) {
            $log_data = [ 'code' => Djebel_Plugin_Rate_Limit::CODE_RULES_UNREADABLE, 'file' => $rules_file, ];

            Dj_App_Log::error($log_data, __METHOD__);
            $parsed_sections = [];
            $defaults = Djebel_Plugin_Rate_Limit::FALLBACK_DEFAULTS;
        } else {
            $defaults = Dj_App_Util::getField(Djebel_Plugin_Rate_Limit::DEFAULTS_SECTION, $parsed_sections, []);
        }

        $prefix_len = strlen(Djebel_Plugin_Rate_Limit::RULES_SECTION_PREFIX);
        $rules = [];

        foreach ($parsed_sections as $section_name => $section_data) {
            if (strpos($section_name, Djebel_Plugin_Rate_Limit::RULES_SECTION_PREFIX) !== 0) {
                continue;
            }

            $rule_name = substr($section_name, $prefix_len);
            $rules[$rule_name] = $section_data;
        }

        // The site's options change what ships: their defaults override the file's, and a rule of
        // a shipped name changes only the fields it sets.
        $options_obj = Dj_App_Options::getInstance();
        $site_defaults = $options_obj->get(Djebel_Plugin_Rate_Limit::DEFAULTS_SECTION, []);
        $site_rules = $options_obj->get(Djebel_Plugin_Rate_Limit::RULES_SECTION, []);

        if (is_array($site_defaults)) {
            $defaults = array_merge($defaults, $site_defaults);
        }

        if (is_array($site_rules)) {
            foreach ($site_rules as $rule_name => $site_rule) {
                if (!is_array($site_rule)) {
                    continue;
                }

                $shipped_rule = empty($rules[$rule_name]) ? [] : $rules[$rule_name];
                $rules[$rule_name] = array_merge($shipped_rule, $site_rule);
            }
        }

        $rules = Dj_App_Hooks::applyFilter(Djebel_Plugin_Rate_Limit::FILTER_RULES, $rules, $ctx);
        $ready_rules = [];

        foreach ($rules as $rule_name => $rule) {
            if (!is_array($rule)) {
                continue;
            }

            $merged_rule = array_merge($defaults, $rule);
            $pattern = Dj_App_Util::getField('pattern', $merged_rule);
            $max_requests = Dj_App_Util::getField('max_requests', $merged_rule, 0);

            if (empty($pattern) || $max_requests <= 0) {
                continue;
            }

            $window_seconds = Dj_App_Util::getField('window_seconds', $merged_rule, 0);
            $subnet_max_requests_multiplier = Dj_App_Util::getField('subnet_max_requests_multiplier', $merged_rule, 0);

            // The counter keys need both: a window of 0 would divide by zero, and a multiplier of 0
            // would close the subnet before its first request.
            if ($window_seconds <= 0 || $subnet_max_requests_multiplier <= 0) {
                continue;
            }

            $count_successes = Dj_App_Util::getField('count_successes', $merged_rule);
            $over_limit_fake_success = Dj_App_Util::getField('over_limit_fake_success', $merged_rule);
            $is_count_successes = Dj_App_Util::isEnabled($count_successes);
            $is_over_limit_fake_success = Dj_App_Util::isEnabled($over_limit_fake_success);

            $ready_rules[$rule_name] = [
                'pattern' => $pattern,
                'max_requests' => $max_requests,
                'window_seconds' => $window_seconds,
                'subnet_max_requests_multiplier' => $subnet_max_requests_multiplier,
                'count_successes' => $is_count_successes,
                'over_limit_fake_success' => $is_over_limit_fake_success,
            ];
        }

        return $ready_rules;
    }

    /**
     * The rule a route falls under: the most specific pattern that matches, the first listed
     * between two of one kind.
     * @param string $route as buildRoute() makes it
     * @return array the rule with its 'name' added, or [] when none matches
     */
    public function findRule($route)
    {
        $found_rule = [];
        $found_tier = 0;
        $rules_ctx = [ 'route' => $route, ];
        $rules = $this->getRules($rules_ctx);

        foreach ($rules as $rule_name => $rule) {
            $alternatives = explode('|', $rule['pattern']);

            foreach ($alternatives as $alternative) {
                $alternative_norm = $this->normalizeName($alternative);
                $is_match = Dj_App_String_Util::matchesPattern($route, $alternative_norm);

                if (empty($is_match)) {
                    continue;
                }

                $tier = $this->getPatternTier($alternative_norm);

                if (empty($found_tier) || $tier < $found_tier) {
                    $found_tier = $tier;
                    $found_rule = $rule;
                    $found_rule['name'] = $rule_name;
                }
            }

            // Nothing beats an exact match.
            if ($found_tier == Djebel_Plugin_Rate_Limit::TIER_EXACT) {
                break;
            }
        }

        return $found_rule;
    }

    /**
     * How specific a pattern is, lower being more specific.
     * @param string $pattern one alternative, normalized
     * @return int a TIER_* value
     */
    public function getPatternTier($pattern)
    {
        if ($pattern == '*') {
            return Djebel_Plugin_Rate_Limit::TIER_ANY;
        }

        $star_pos = strpos($pattern, '*');

        if ($star_pos === false) {
            return Djebel_Plugin_Rate_Limit::TIER_EXACT;
        }

        if ($star_pos == 0) {
            return Djebel_Plugin_Rate_Limit::TIER_SUFFIX;
        }

        return Djebel_Plugin_Rate_Limit::TIER_PREFIX;
    }

    /**
     * The route a request names: <module>[.<sub_module>]/<action>, normalized. The sub-module
     * joins with a dot, so the one slash always comes before the action and '*' + '/send*' can
     * only mean an action that starts with "send".
     * @param array $params module, sub_module, action
     * @return string '' when the module or the action is missing
     */
    public function buildRoute($params = [])
    {
        $module = empty($params['module']) ? '' : $params['module'];
        $sub_module = empty($params['sub_module']) ? '' : $params['sub_module'];
        $action = empty($params['action']) ? '' : $params['action'];

        if (empty($module) || empty($action)) {
            return '';
        }

        $has_sub_module = !empty($sub_module);

        if ($has_sub_module) {
            $scope = $module . '.' . $sub_module;
        } else {
            $scope = $module;
        }

        $route = $scope . '/' . $action;
        $route = $this->normalizeName($route);

        return $route;
    }

    /**
     * A name with case, '_', '-' and spaces dropped, the form routes and patterns are compared in.
     * @param string $name
     * @return string
     */
    public function normalizeName($name)
    {
        $name_norm = strtolower($name);
        $name_norm = str_replace([ '_', '-', ' ', ], '', $name_norm);

        return $name_norm;
    }

    /**
     * The counters a request spends: its IP, its subnet at the rule's
     * subnet_max_requests_multiplier times the budget, and its signed-in user when there is one.
     * Each is named after the rule that matched, so a wildcard rule's budget is shared by every
     * route it covers and an exact one is its own route's; the window's number in the name starts
     * a fresh count when the window rolls. Each key is a hash of that name, ready to hand to the
     * cache, and lives until its window ends.
     * @param array $params rule (as findRule() returns it), ip, user_id, now
     * @return array key type => key, max_requests, ttl; [] without a rule
     */
    public function buildCounterKeys($params = [])
    {
        $rule = Dj_App_Util::getField('rule', $params, []);

        if (empty($rule)) {
            return [];
        }

        $window_seconds = $rule['window_seconds'];
        $max_requests = $rule['max_requests'];
        $now = empty($params['now']) ? time() : $params['now'];
        $bucket = intdiv($now, $window_seconds);
        $expires_at = ($bucket + 1) * $window_seconds;
        $ttl = $expires_at - $now;
        $scope = $rule['name'] . '|' . $window_seconds . '|' . $bucket;
        $counter_keys = [];

        $ip = empty($params['ip']) ? '' : $params['ip'];

        if (!empty($ip)) {
            $subnet_key = $this->getSubnetKey($ip);
            $ip_name = 'ip|' . $ip . '|' . $scope;
            $ip_key = sha1($ip_name);
            $subnet_name = 'net|' . $subnet_key . '|' . $scope;
            $subnet_counter_key = sha1($subnet_name);
            $subnet_max_requests = $max_requests * $rule['subnet_max_requests_multiplier'];

            $counter_keys['ip'] = [
                'key' => $ip_key,
                'max_requests' => $max_requests,
                'ttl' => $ttl,
            ];

            $counter_keys['subnet'] = [
                'key' => $subnet_counter_key,
                'max_requests' => $subnet_max_requests,
                'ttl' => $ttl,
            ];
        }

        $user_id = empty($params['user_id']) ? '' : $params['user_id'];

        if (!empty($user_id)) {
            $user_name = 'user|' . $user_id . '|' . $scope;
            $user_key = sha1($user_name);

            $counter_keys['user'] = [
                'key' => $user_key,
                'max_requests' => $max_requests,
                'ttl' => $ttl,
            ];
        }

        return $counter_keys;
    }

    /**
     * The /24 (IPv4) or /64 (IPv6) network an IP sits in, as hex, so callers rotating addresses
     * inside one range share a counter. An address that does not parse is its own key.
     * @param string $ip
     * @return string
     */
    public function getSubnetKey($ip)
    {
        $valid_ip = filter_var($ip, FILTER_VALIDATE_IP);

        if (empty($valid_ip)) {
            return $ip;
        }

        $packed = inet_pton($ip);
        $packed_len = strlen($packed);

        if ($packed_len == 4) {
            $bits = Djebel_Plugin_Rate_Limit::CIDR_V4_BITS;
        } elseif ($packed_len == 16) {
            $bits = Djebel_Plugin_Rate_Limit::CIDR_V6_BITS;
        } else {
            return $ip;
        }

        $keep_bytes = intdiv($bits, 8);
        $prefix = substr($packed, 0, $keep_bytes);
        $subnet_key = bin2hex($prefix);

        return $subnet_key;
    }
}
