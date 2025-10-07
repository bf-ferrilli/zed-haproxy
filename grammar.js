module.exports = grammar({
  name: "haproxy",

  extras: ($) => [/\s/, $.comment],

  conflicts: ($) => [[$.arguments], [$.section]],

  rules: {
    source_file: ($) => repeat($._statement),

    _statement: ($) => choice($.section, $.directive, $.comment),

    comment: ($) => /#.*/,

    section: ($) =>
      seq(
        field("type", $.section_name),
        optional(field("name", $.identifier)),
        optional(repeat($.directive)),
      ),

    section_name: ($) =>
      choice(
        "global",
        "defaults",
        "frontend",
        "backend",
        "listen",
        "peers",
        "resolvers",
        "userlist",
        "aggregations",
      ),

    directive: ($) =>
      seq(
        field("keyword", choice($.keyword, $.keyword_combination)),
        field("args", optional($.arguments)),
      ),

    keyword: ($) =>
      choice(
        "acl",
        "bind",
        "server",
        "balance",
        "mode",
        "maxconn",
        "user",
        "group",
        "daemon",
        "log",
        "retries",
        "cookie",
        "errorfile",
        "default_backend",
        "use_backend",
        "compression",
        "redirect",
        "source",
        "id",
        "disabled",
        "enabled",
        "dispatch",
        "backlog",
        "description",
        "chroot",
        "ca-base",
        "crt-base",
        "nbproc",
        "cpu-map",
        "lua-load",
        "monitor-net",
        "monitor-uri",
        "grace",
        "hash-type",
        "force-persist",
        "ignore-persist",
        "bind-process",
        "default-server",
        "log-format",
        "unique-id-format",
        "unique-id-header",
        "nameserver",
        "peer",
        "resolution_pool_size",
        "resolve_retries",
        "reqadd",
        "reqallow",
        "reqdel",
        "reqdeny",
        "reqiallow",
        "reqidel",
        "reqideny",
        "reqipass",
        "reqirep",
        "reqisetbe",
        "reqitarpit",
        "reqpass",
        "reqrep",
        "reqsetbe",
        "reqtarpit",
        "rspadd",
        "rspdel",
        "rspdeny",
        "rspidel",
        "rspideny",
        "rspirep",
        "rsprep",
      ),

    keyword_combination: ($) =>
      choice(
        seq("option", $.option_value),
        seq("timeout", $.timeout_type),
        seq("stats", $.stats_option),
        seq("http-request", $.http_action),
        seq("http-response", $.http_action),
        seq("http-check", $.http_check_option),
        seq("tcp-request", $.tcp_request_type),
        seq("tcp-response", $.tcp_response_type),
        seq("stick", $.stick_option),
        seq("stick-table", $.arguments),
        seq("capture", $.capture_type),
        seq("use-server", $.arguments),
        seq("monitor", "fail"),
        seq("rate-limit", "sessions"),
        seq("persist", "rdp-cookie"),
      ),

    option_value: ($) =>
      choice(
        "httplog",
        "tcplog",
        "httpchk",
        "forwardfor",
        "redispatch",
        "abortonclose",
        "accept-invalid-http-request",
        "accept-invalid-http-response",
        "allbackups",
        "checkcache",
        "clitcpka",
        "contstats",
        "dontlog-normal",
        "dontlognull",
        "forceclose",
        "http-no-delay",
        "http-pretend-keepalive",
        "http-server-close",
        "http-use-proxy-header",
        "httpclose",
        "http_proxy",
        "independent-streams",
        "ldap-check",
        "log-health-checks",
        "log-separate-errors",
        "logasap",
        "mysql-check",
        "pgsql-check",
        "nolinger",
        "originalto",
        "persist",
        "redis-check",
        "smtpchk",
        "socket-stats",
        "splice-auto",
        "splice-request",
        "splice-response",
        "srvtcpka",
        "ssl-hello-chk",
        "tcp-check",
        "tcp-smart-accept",
        "tcp-smart-connect",
        "tcpka",
        "transparent",
      ),

    timeout_type: ($) =>
      choice(
        "check",
        "client",
        "connect",
        "http-keep-alive",
        "http-request",
        "queue",
        "server",
        "tarpit",
        "tunnel",
      ),

    stats_option: ($) =>
      choice(
        "enable",
        "uri",
        "realm",
        "auth",
        "refresh",
        "admin",
        "hide-version",
        "show-desc",
        "show-legends",
        "show-node",
        "socket",
        "timeout",
        "http-request",
        "bind-process",
        "scope",
      ),

    http_action: ($) =>
      choice(
        "add-header",
        "set-header",
        "del-header",
        "replace-header",
        "replace-value",
        "deny",
        "allow",
        "auth",
        "redirect",
        "set-log-level",
        "set-nice",
        "set-tos",
        "set-mark",
        "add-acl",
        "del-acl",
        "set-map",
        "del-map",
      ),

    http_check_option: ($) => choice("disable-on-404", "expect", "send-state"),

    tcp_request_type: ($) => choice("connection", "content", "inspect-delay"),

    tcp_response_type: ($) => choice("content", "inspect-delay"),

    stick_option: ($) =>
      choice("match", "on", "store-request", "store-response"),

    capture_type: ($) =>
      choice(
        seq("cookie", $.arguments),
        seq("request", "header", $.arguments),
        seq("response", "header", $.arguments),
      ),

    arguments: ($) => repeat1($._argument),

    _argument: ($) =>
      choice(
        $.string,
        $.ip_address,
        $.wildcard_bind,
        $.number,
        $.time_value,
        $.parameter,
        $.operator,
        $.control_flow,
        $.identifier,
        $.path,
      ),

    string: ($) => /"[^"]*"/,

    ip_address: ($) =>
      /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):\d{1,5}/,

    wildcard_bind: ($) => /\*:\d{1,5}/,

    number: ($) => /\d+/,

    time_value: ($) => /\d+(ms|s|m|h|d)/,

    parameter: ($) => /%\[[^\]]+\]/,

    operator: ($) => choice("or", "||", "!"),

    control_flow: ($) => choice("if", "unless", "rewrite"),

    identifier: ($) => /[a-zA-Z_][a-zA-Z0-9_\-]*/,

    path: ($) => /\/[-+\w\/\\|^.:;@%!$*?=~(){}\[\]`"'#<>&]*/,
  },
});
