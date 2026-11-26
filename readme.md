# djebel-rate-limit

Request budgets per route for djebel apps and anything that loads djebel. Every route has a budget
the moment it exists: smart defaults decide it from what the action does, and an app adds or
replaces a rule through one filter only where a default does not fit. The defaults are generic,
named after kinds of action and never after one app's routes; an app's own routes get their rules
from that app's listener.

## Using it

```php
$rate_limit_obj = Djebel_Plugin_Rate_Limit::getInstance();

$req_params = [
    'module' => 'users',
    'sub_module' => '',           // optional
    'action' => 'auth',
    'ip' => $visitor_ip,          // the client's address, not a proxy's
    'user_id' => $user_id,        // optional: the signed-in user, from a key the app verified
];

// Before the route runs: reads the counters, adds nothing.
$check_res_obj = $rate_limit_obj->check($req_params);

if (!empty($check_res_obj->over_limit)) {
    // turn the request away; $check_res_obj->rule['over_limit_fake_success'] asks for a fake success
}

// After the response: records the request.
$req_params['is_success'] = $is_success;
$count_res_obj = $rate_limit_obj->count($req_params);
```

The caller decides what over the limit looks like: an error, or a fake success where the rule sets
`over_limit_fake_success`, so brute-force tooling cannot tell a block from a real answer.

## Routes and patterns

A route is `<module>[.<sub_module>]/<action>`: `users/auth`, `users.blocks/block`. Case, `_`, `-`
and spaces are ignored on both sides, so `reset_password`, `resetPassword` and `reset-password`
are one route.

| Pattern | Matches |
|---|---|
| `users/auth` | that route only |
| `users/*` | every action of the `users` module |
| `*/delete` | every action named `delete` |
| `*/send*` | every action starting with `send` |
| `*` | everything |
| `a\|b` | either |

The most specific pattern that matches wins: an exact route, then `prefix*`, then `*suffix` or
`*contains*`, then `*`. Between two of one kind, the first listed wins.

## Rules

Each rule has a name and these fields:

| Field | Meaning |
|---|---|
| `pattern` | the routes it covers: one pattern, or several joined with `\|` |
| `max_requests` | requests allowed per IP per window |
| `window_seconds` | the window's length |
| `subnet_max_requests_multiplier` | a subnet (/24 for IPv4, /64 for IPv6) gets this many times `max_requests` |
| `count_successes` | a successful request spends the budget too; off, only failures count |
| `over_limit_fake_success` | over the limit, the caller answers with a fake success |

The flags take `1`, `true`, `yes` or `on`. A signed-in user gets `max_requests` of their own. A
rule's budget is shared by every route it covers. A rule without a `pattern` or a `max_requests`
limits nothing and is left out.

## The smart defaults

They ship in `default_rules.ini`. Every rule starts from the defaults section and sets only what
differs:

```ini
[plugins.djebel-plugin-rate-limit.defaults]
window_seconds = 3600
subnet_max_requests_multiplier = 8
count_successes = 1
over_limit_fake_success = 0

[plugins.djebel-plugin-rate-limit.rules.sign_in]
pattern = "*/auth|*/login"
max_requests = 20
count_successes = 0
over_limit_fake_success = 1
```

| Rule | Patterns | `max_requests` | Counts |
|---|---|---|---|
| `sign_in` | `*/auth`, `*/login` | 20 | failures, fake success |
| `account_secrets` | `*/reset_password*`, `*/change_password*`, `*/change_email*`, `*/verify*` | 10 | failures, fake success |
| `lookups` | `*/check*`, `*/find*`, `*/lookup*`, `*/search*` | 120 | every request |
| `writes` | `*/create`, `*/upsert`, `*/save*`, `*/update*`, `*/set*`, `*/add*`, `*/delete*`, `*/remove*` | 600 | every request |
| `reads` | `*/get*`, `*/list*` | 2400 | every request |
| `any` | `*` | 1200 | every request |

When the file cannot be read, it is logged with the code `app.plugin.rate_limit.rules_unreadable`,
the same defaults are used from the plugin's code, and only the rules an app adds through the
filter limit.

## A site's own rules

A site keeps its own rules in its `app.ini`, in the same sections as `default_rules.ini`. Its
defaults override the shipped ones, a rule with a shipped name changes only the fields it sets, a
new name adds a rule, and a `max_requests` of 0 switches one off:

```ini
[plugins.djebel-plugin-rate-limit.defaults]
window_seconds = 600

[plugins.djebel-plugin-rate-limit.rules.users_delete]
pattern = "users/delete"
max_requests = 10
count_successes = 0
over_limit_fake_success = 1

[plugins.djebel-plugin-rate-limit.rules.sign_in]
max_requests = 5
```

Project specifics belong there, never in this plugin.

## Adding or replacing a rule in code

```php
Dj_App_Hooks::addFilter('app.plugin.rate_limit.filter.rules', [ $my_obj, 'filterRateLimitRules' ]);

public function filterRateLimitRules($rules, $ctx = [])
{
    $new_rules = $rules;
    $new_rules['web_send'] = [ 'pattern' => 'web/send', 'max_requests' => 10, ];
    $new_rules['sign_in']['max_requests'] = 5;
    $new_rules['reads']['max_requests'] = 0;

    return $new_rules;
}
```

A new name adds a rule, an existing name changes it, and a `max_requests` of 0 switches it off. The
defaults fill in whatever a rule leaves out, the rules a listener adds included. `$ctx['route']` is
the route being matched.

## Where the counters live

In djebel's cache, under the `djebel-rate-limit` dir, through `Dj_App_Cache::get()` and
`Dj_App_Cache::increment()`. The cache counts in APCu where the running PHP has it, atomically and
without files, and in locked files otherwise, such as on a command line. Each counter lives until
its window ends. Another store, such as Valkey, comes in through the cache's own
`app.cache.backend` filter, and this plugin needs no change for it.

`Dj_App_Cache::removeAll([ 'plugin' => 'djebel-rate-limit', ])` clears every counter.

## Requirements

PHP 7.4 or later, and djebel's core: `Dj_App_Hooks`, `Dj_App_String_Util::matchesPattern()`,
`Dj_App_Util::getField()` and `isEnabled()`, `Dj_App_Cache` with `increment()`, `Dj_App_Result`,
`Dj_App_Log`.

## Tests

From a djebel-app checkout: `php tools/testing/run.php <this plugin's dir>`.
