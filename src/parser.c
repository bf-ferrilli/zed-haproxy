#include <tree_sitter/parser.h>

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif

#ifdef _MSC_VER
#pragma optimize("", off)
#elif defined(__clang__)
#pragma clang optimize off
#elif defined(__GNUC__)
#pragma GCC optimize ("O0")
#endif

#define LANGUAGE_VERSION 14
#define STATE_COUNT 46
#define LARGE_STATE_COUNT 29
#define SYMBOL_COUNT 223
#define ALIAS_COUNT 0
#define TOKEN_COUNT 200
#define EXTERNAL_TOKEN_COUNT 0
#define FIELD_COUNT 4
#define MAX_ALIAS_SEQUENCE_LENGTH 3
#define PRODUCTION_ID_COUNT 5

enum {
  sym_comment = 1,
  anon_sym_global = 2,
  anon_sym_defaults = 3,
  anon_sym_frontend = 4,
  anon_sym_backend = 5,
  anon_sym_listen = 6,
  anon_sym_peers = 7,
  anon_sym_resolvers = 8,
  anon_sym_userlist = 9,
  anon_sym_aggregations = 10,
  anon_sym_acl = 11,
  anon_sym_bind = 12,
  anon_sym_server = 13,
  anon_sym_balance = 14,
  anon_sym_mode = 15,
  anon_sym_maxconn = 16,
  anon_sym_user = 17,
  anon_sym_group = 18,
  anon_sym_daemon = 19,
  anon_sym_log = 20,
  anon_sym_retries = 21,
  anon_sym_cookie = 22,
  anon_sym_errorfile = 23,
  anon_sym_default_backend = 24,
  anon_sym_use_backend = 25,
  anon_sym_compression = 26,
  anon_sym_redirect = 27,
  anon_sym_source = 28,
  anon_sym_id = 29,
  anon_sym_disabled = 30,
  anon_sym_enabled = 31,
  anon_sym_dispatch = 32,
  anon_sym_backlog = 33,
  anon_sym_description = 34,
  anon_sym_chroot = 35,
  anon_sym_ca_DASHbase = 36,
  anon_sym_crt_DASHbase = 37,
  anon_sym_nbproc = 38,
  anon_sym_cpu_DASHmap = 39,
  anon_sym_lua_DASHload = 40,
  anon_sym_monitor_DASHnet = 41,
  anon_sym_monitor_DASHuri = 42,
  anon_sym_grace = 43,
  anon_sym_hash_DASHtype = 44,
  anon_sym_force_DASHpersist = 45,
  anon_sym_ignore_DASHpersist = 46,
  anon_sym_bind_DASHprocess = 47,
  anon_sym_default_DASHserver = 48,
  anon_sym_log_DASHformat = 49,
  anon_sym_unique_DASHid_DASHformat = 50,
  anon_sym_unique_DASHid_DASHheader = 51,
  anon_sym_nameserver = 52,
  anon_sym_peer = 53,
  anon_sym_resolution_pool_size = 54,
  anon_sym_resolve_retries = 55,
  anon_sym_reqadd = 56,
  anon_sym_reqallow = 57,
  anon_sym_reqdel = 58,
  anon_sym_reqdeny = 59,
  anon_sym_reqiallow = 60,
  anon_sym_reqidel = 61,
  anon_sym_reqideny = 62,
  anon_sym_reqipass = 63,
  anon_sym_reqirep = 64,
  anon_sym_reqisetbe = 65,
  anon_sym_reqitarpit = 66,
  anon_sym_reqpass = 67,
  anon_sym_reqrep = 68,
  anon_sym_reqsetbe = 69,
  anon_sym_reqtarpit = 70,
  anon_sym_rspadd = 71,
  anon_sym_rspdel = 72,
  anon_sym_rspdeny = 73,
  anon_sym_rspidel = 74,
  anon_sym_rspideny = 75,
  anon_sym_rspirep = 76,
  anon_sym_rsprep = 77,
  anon_sym_option = 78,
  anon_sym_timeout = 79,
  anon_sym_stats = 80,
  anon_sym_http_DASHrequest = 81,
  anon_sym_http_DASHresponse = 82,
  anon_sym_http_DASHcheck = 83,
  anon_sym_tcp_DASHrequest = 84,
  anon_sym_tcp_DASHresponse = 85,
  anon_sym_stick = 86,
  anon_sym_stick_DASHtable = 87,
  anon_sym_capture = 88,
  anon_sym_use_DASHserver = 89,
  anon_sym_monitor = 90,
  anon_sym_fail = 91,
  anon_sym_rate_DASHlimit = 92,
  anon_sym_sessions = 93,
  anon_sym_persist = 94,
  anon_sym_rdp_DASHcookie = 95,
  anon_sym_httplog = 96,
  anon_sym_tcplog = 97,
  anon_sym_httpchk = 98,
  anon_sym_forwardfor = 99,
  anon_sym_redispatch = 100,
  anon_sym_abortonclose = 101,
  anon_sym_accept_DASHinvalid_DASHhttp_DASHrequest = 102,
  anon_sym_accept_DASHinvalid_DASHhttp_DASHresponse = 103,
  anon_sym_allbackups = 104,
  anon_sym_checkcache = 105,
  anon_sym_clitcpka = 106,
  anon_sym_contstats = 107,
  anon_sym_dontlog_DASHnormal = 108,
  anon_sym_dontlognull = 109,
  anon_sym_forceclose = 110,
  anon_sym_http_DASHno_DASHdelay = 111,
  anon_sym_http_DASHpretend_DASHkeepalive = 112,
  anon_sym_http_DASHserver_DASHclose = 113,
  anon_sym_http_DASHuse_DASHproxy_DASHheader = 114,
  anon_sym_httpclose = 115,
  anon_sym_http_proxy = 116,
  anon_sym_independent_DASHstreams = 117,
  anon_sym_ldap_DASHcheck = 118,
  anon_sym_log_DASHhealth_DASHchecks = 119,
  anon_sym_log_DASHseparate_DASHerrors = 120,
  anon_sym_logasap = 121,
  anon_sym_mysql_DASHcheck = 122,
  anon_sym_pgsql_DASHcheck = 123,
  anon_sym_nolinger = 124,
  anon_sym_originalto = 125,
  anon_sym_redis_DASHcheck = 126,
  anon_sym_smtpchk = 127,
  anon_sym_socket_DASHstats = 128,
  anon_sym_splice_DASHauto = 129,
  anon_sym_splice_DASHrequest = 130,
  anon_sym_splice_DASHresponse = 131,
  anon_sym_srvtcpka = 132,
  anon_sym_ssl_DASHhello_DASHchk = 133,
  anon_sym_tcp_DASHcheck = 134,
  anon_sym_tcp_DASHsmart_DASHaccept = 135,
  anon_sym_tcp_DASHsmart_DASHconnect = 136,
  anon_sym_tcpka = 137,
  anon_sym_transparent = 138,
  anon_sym_check = 139,
  anon_sym_client = 140,
  anon_sym_connect = 141,
  anon_sym_http_DASHkeep_DASHalive = 142,
  anon_sym_queue = 143,
  anon_sym_tarpit = 144,
  anon_sym_tunnel = 145,
  anon_sym_enable = 146,
  anon_sym_uri = 147,
  anon_sym_realm = 148,
  anon_sym_auth = 149,
  anon_sym_refresh = 150,
  anon_sym_admin = 151,
  anon_sym_hide_DASHversion = 152,
  anon_sym_show_DASHdesc = 153,
  anon_sym_show_DASHlegends = 154,
  anon_sym_show_DASHnode = 155,
  anon_sym_socket = 156,
  anon_sym_scope = 157,
  anon_sym_add_DASHheader = 158,
  anon_sym_set_DASHheader = 159,
  anon_sym_del_DASHheader = 160,
  anon_sym_replace_DASHheader = 161,
  anon_sym_replace_DASHvalue = 162,
  anon_sym_deny = 163,
  anon_sym_allow = 164,
  anon_sym_set_DASHlog_DASHlevel = 165,
  anon_sym_set_DASHnice = 166,
  anon_sym_set_DASHtos = 167,
  anon_sym_set_DASHmark = 168,
  anon_sym_add_DASHacl = 169,
  anon_sym_del_DASHacl = 170,
  anon_sym_set_DASHmap = 171,
  anon_sym_del_DASHmap = 172,
  anon_sym_disable_DASHon_DASH404 = 173,
  anon_sym_expect = 174,
  anon_sym_send_DASHstate = 175,
  anon_sym_connection = 176,
  anon_sym_content = 177,
  anon_sym_inspect_DASHdelay = 178,
  anon_sym_match = 179,
  anon_sym_on = 180,
  anon_sym_store_DASHrequest = 181,
  anon_sym_store_DASHresponse = 182,
  anon_sym_request = 183,
  anon_sym_header = 184,
  anon_sym_response = 185,
  sym_string = 186,
  sym_ip_address = 187,
  sym_wildcard_bind = 188,
  sym_number = 189,
  sym_time_value = 190,
  sym_parameter = 191,
  anon_sym_or = 192,
  anon_sym_PIPE_PIPE = 193,
  anon_sym_BANG = 194,
  anon_sym_if = 195,
  anon_sym_unless = 196,
  anon_sym_rewrite = 197,
  sym_identifier = 198,
  sym_path = 199,
  sym_source_file = 200,
  sym__statement = 201,
  sym_section = 202,
  sym_section_name = 203,
  sym_directive = 204,
  sym_keyword = 205,
  sym_keyword_combination = 206,
  sym_option_value = 207,
  sym_timeout_type = 208,
  sym_stats_option = 209,
  sym_http_action = 210,
  sym_http_check_option = 211,
  sym_tcp_request_type = 212,
  sym_tcp_response_type = 213,
  sym_stick_option = 214,
  sym_capture_type = 215,
  sym_arguments = 216,
  sym__argument = 217,
  sym_operator = 218,
  sym_control_flow = 219,
  aux_sym_source_file_repeat1 = 220,
  aux_sym_section_repeat1 = 221,
  aux_sym_arguments_repeat1 = 222,
};

static const char * const ts_symbol_names[] = {
  [ts_builtin_sym_end] = "end",
  [sym_comment] = "comment",
  [anon_sym_global] = "global",
  [anon_sym_defaults] = "defaults",
  [anon_sym_frontend] = "frontend",
  [anon_sym_backend] = "backend",
  [anon_sym_listen] = "listen",
  [anon_sym_peers] = "peers",
  [anon_sym_resolvers] = "resolvers",
  [anon_sym_userlist] = "userlist",
  [anon_sym_aggregations] = "aggregations",
  [anon_sym_acl] = "acl",
  [anon_sym_bind] = "bind",
  [anon_sym_server] = "server",
  [anon_sym_balance] = "balance",
  [anon_sym_mode] = "mode",
  [anon_sym_maxconn] = "maxconn",
  [anon_sym_user] = "user",
  [anon_sym_group] = "group",
  [anon_sym_daemon] = "daemon",
  [anon_sym_log] = "log",
  [anon_sym_retries] = "retries",
  [anon_sym_cookie] = "cookie",
  [anon_sym_errorfile] = "errorfile",
  [anon_sym_default_backend] = "default_backend",
  [anon_sym_use_backend] = "use_backend",
  [anon_sym_compression] = "compression",
  [anon_sym_redirect] = "redirect",
  [anon_sym_source] = "source",
  [anon_sym_id] = "id",
  [anon_sym_disabled] = "disabled",
  [anon_sym_enabled] = "enabled",
  [anon_sym_dispatch] = "dispatch",
  [anon_sym_backlog] = "backlog",
  [anon_sym_description] = "description",
  [anon_sym_chroot] = "chroot",
  [anon_sym_ca_DASHbase] = "ca-base",
  [anon_sym_crt_DASHbase] = "crt-base",
  [anon_sym_nbproc] = "nbproc",
  [anon_sym_cpu_DASHmap] = "cpu-map",
  [anon_sym_lua_DASHload] = "lua-load",
  [anon_sym_monitor_DASHnet] = "monitor-net",
  [anon_sym_monitor_DASHuri] = "monitor-uri",
  [anon_sym_grace] = "grace",
  [anon_sym_hash_DASHtype] = "hash-type",
  [anon_sym_force_DASHpersist] = "force-persist",
  [anon_sym_ignore_DASHpersist] = "ignore-persist",
  [anon_sym_bind_DASHprocess] = "bind-process",
  [anon_sym_default_DASHserver] = "default-server",
  [anon_sym_log_DASHformat] = "log-format",
  [anon_sym_unique_DASHid_DASHformat] = "unique-id-format",
  [anon_sym_unique_DASHid_DASHheader] = "unique-id-header",
  [anon_sym_nameserver] = "nameserver",
  [anon_sym_peer] = "peer",
  [anon_sym_resolution_pool_size] = "resolution_pool_size",
  [anon_sym_resolve_retries] = "resolve_retries",
  [anon_sym_reqadd] = "reqadd",
  [anon_sym_reqallow] = "reqallow",
  [anon_sym_reqdel] = "reqdel",
  [anon_sym_reqdeny] = "reqdeny",
  [anon_sym_reqiallow] = "reqiallow",
  [anon_sym_reqidel] = "reqidel",
  [anon_sym_reqideny] = "reqideny",
  [anon_sym_reqipass] = "reqipass",
  [anon_sym_reqirep] = "reqirep",
  [anon_sym_reqisetbe] = "reqisetbe",
  [anon_sym_reqitarpit] = "reqitarpit",
  [anon_sym_reqpass] = "reqpass",
  [anon_sym_reqrep] = "reqrep",
  [anon_sym_reqsetbe] = "reqsetbe",
  [anon_sym_reqtarpit] = "reqtarpit",
  [anon_sym_rspadd] = "rspadd",
  [anon_sym_rspdel] = "rspdel",
  [anon_sym_rspdeny] = "rspdeny",
  [anon_sym_rspidel] = "rspidel",
  [anon_sym_rspideny] = "rspideny",
  [anon_sym_rspirep] = "rspirep",
  [anon_sym_rsprep] = "rsprep",
  [anon_sym_option] = "option",
  [anon_sym_timeout] = "timeout",
  [anon_sym_stats] = "stats",
  [anon_sym_http_DASHrequest] = "http-request",
  [anon_sym_http_DASHresponse] = "http-response",
  [anon_sym_http_DASHcheck] = "http-check",
  [anon_sym_tcp_DASHrequest] = "tcp-request",
  [anon_sym_tcp_DASHresponse] = "tcp-response",
  [anon_sym_stick] = "stick",
  [anon_sym_stick_DASHtable] = "stick-table",
  [anon_sym_capture] = "capture",
  [anon_sym_use_DASHserver] = "use-server",
  [anon_sym_monitor] = "monitor",
  [anon_sym_fail] = "fail",
  [anon_sym_rate_DASHlimit] = "rate-limit",
  [anon_sym_sessions] = "sessions",
  [anon_sym_persist] = "persist",
  [anon_sym_rdp_DASHcookie] = "rdp-cookie",
  [anon_sym_httplog] = "httplog",
  [anon_sym_tcplog] = "tcplog",
  [anon_sym_httpchk] = "httpchk",
  [anon_sym_forwardfor] = "forwardfor",
  [anon_sym_redispatch] = "redispatch",
  [anon_sym_abortonclose] = "abortonclose",
  [anon_sym_accept_DASHinvalid_DASHhttp_DASHrequest] = "accept-invalid-http-request",
  [anon_sym_accept_DASHinvalid_DASHhttp_DASHresponse] = "accept-invalid-http-response",
  [anon_sym_allbackups] = "allbackups",
  [anon_sym_checkcache] = "checkcache",
  [anon_sym_clitcpka] = "clitcpka",
  [anon_sym_contstats] = "contstats",
  [anon_sym_dontlog_DASHnormal] = "dontlog-normal",
  [anon_sym_dontlognull] = "dontlognull",
  [anon_sym_forceclose] = "forceclose",
  [anon_sym_http_DASHno_DASHdelay] = "http-no-delay",
  [anon_sym_http_DASHpretend_DASHkeepalive] = "http-pretend-keepalive",
  [anon_sym_http_DASHserver_DASHclose] = "http-server-close",
  [anon_sym_http_DASHuse_DASHproxy_DASHheader] = "http-use-proxy-header",
  [anon_sym_httpclose] = "httpclose",
  [anon_sym_http_proxy] = "http_proxy",
  [anon_sym_independent_DASHstreams] = "independent-streams",
  [anon_sym_ldap_DASHcheck] = "ldap-check",
  [anon_sym_log_DASHhealth_DASHchecks] = "log-health-checks",
  [anon_sym_log_DASHseparate_DASHerrors] = "log-separate-errors",
  [anon_sym_logasap] = "logasap",
  [anon_sym_mysql_DASHcheck] = "mysql-check",
  [anon_sym_pgsql_DASHcheck] = "pgsql-check",
  [anon_sym_nolinger] = "nolinger",
  [anon_sym_originalto] = "originalto",
  [anon_sym_redis_DASHcheck] = "redis-check",
  [anon_sym_smtpchk] = "smtpchk",
  [anon_sym_socket_DASHstats] = "socket-stats",
  [anon_sym_splice_DASHauto] = "splice-auto",
  [anon_sym_splice_DASHrequest] = "splice-request",
  [anon_sym_splice_DASHresponse] = "splice-response",
  [anon_sym_srvtcpka] = "srvtcpka",
  [anon_sym_ssl_DASHhello_DASHchk] = "ssl-hello-chk",
  [anon_sym_tcp_DASHcheck] = "tcp-check",
  [anon_sym_tcp_DASHsmart_DASHaccept] = "tcp-smart-accept",
  [anon_sym_tcp_DASHsmart_DASHconnect] = "tcp-smart-connect",
  [anon_sym_tcpka] = "tcpka",
  [anon_sym_transparent] = "transparent",
  [anon_sym_check] = "check",
  [anon_sym_client] = "client",
  [anon_sym_connect] = "connect",
  [anon_sym_http_DASHkeep_DASHalive] = "http-keep-alive",
  [anon_sym_queue] = "queue",
  [anon_sym_tarpit] = "tarpit",
  [anon_sym_tunnel] = "tunnel",
  [anon_sym_enable] = "enable",
  [anon_sym_uri] = "uri",
  [anon_sym_realm] = "realm",
  [anon_sym_auth] = "auth",
  [anon_sym_refresh] = "refresh",
  [anon_sym_admin] = "admin",
  [anon_sym_hide_DASHversion] = "hide-version",
  [anon_sym_show_DASHdesc] = "show-desc",
  [anon_sym_show_DASHlegends] = "show-legends",
  [anon_sym_show_DASHnode] = "show-node",
  [anon_sym_socket] = "socket",
  [anon_sym_scope] = "scope",
  [anon_sym_add_DASHheader] = "add-header",
  [anon_sym_set_DASHheader] = "set-header",
  [anon_sym_del_DASHheader] = "del-header",
  [anon_sym_replace_DASHheader] = "replace-header",
  [anon_sym_replace_DASHvalue] = "replace-value",
  [anon_sym_deny] = "deny",
  [anon_sym_allow] = "allow",
  [anon_sym_set_DASHlog_DASHlevel] = "set-log-level",
  [anon_sym_set_DASHnice] = "set-nice",
  [anon_sym_set_DASHtos] = "set-tos",
  [anon_sym_set_DASHmark] = "set-mark",
  [anon_sym_add_DASHacl] = "add-acl",
  [anon_sym_del_DASHacl] = "del-acl",
  [anon_sym_set_DASHmap] = "set-map",
  [anon_sym_del_DASHmap] = "del-map",
  [anon_sym_disable_DASHon_DASH404] = "disable-on-404",
  [anon_sym_expect] = "expect",
  [anon_sym_send_DASHstate] = "send-state",
  [anon_sym_connection] = "connection",
  [anon_sym_content] = "content",
  [anon_sym_inspect_DASHdelay] = "inspect-delay",
  [anon_sym_match] = "match",
  [anon_sym_on] = "on",
  [anon_sym_store_DASHrequest] = "store-request",
  [anon_sym_store_DASHresponse] = "store-response",
  [anon_sym_request] = "request",
  [anon_sym_header] = "header",
  [anon_sym_response] = "response",
  [sym_string] = "string",
  [sym_ip_address] = "ip_address",
  [sym_wildcard_bind] = "wildcard_bind",
  [sym_number] = "number",
  [sym_time_value] = "time_value",
  [sym_parameter] = "parameter",
  [anon_sym_or] = "or",
  [anon_sym_PIPE_PIPE] = "||",
  [anon_sym_BANG] = "!",
  [anon_sym_if] = "if",
  [anon_sym_unless] = "unless",
  [anon_sym_rewrite] = "rewrite",
  [sym_identifier] = "identifier",
  [sym_path] = "path",
  [sym_source_file] = "source_file",
  [sym__statement] = "_statement",
  [sym_section] = "section",
  [sym_section_name] = "section_name",
  [sym_directive] = "directive",
  [sym_keyword] = "keyword",
  [sym_keyword_combination] = "keyword_combination",
  [sym_option_value] = "option_value",
  [sym_timeout_type] = "timeout_type",
  [sym_stats_option] = "stats_option",
  [sym_http_action] = "http_action",
  [sym_http_check_option] = "http_check_option",
  [sym_tcp_request_type] = "tcp_request_type",
  [sym_tcp_response_type] = "tcp_response_type",
  [sym_stick_option] = "stick_option",
  [sym_capture_type] = "capture_type",
  [sym_arguments] = "arguments",
  [sym__argument] = "_argument",
  [sym_operator] = "operator",
  [sym_control_flow] = "control_flow",
  [aux_sym_source_file_repeat1] = "source_file_repeat1",
  [aux_sym_section_repeat1] = "section_repeat1",
  [aux_sym_arguments_repeat1] = "arguments_repeat1",
};

static const TSSymbol ts_symbol_map[] = {
  [ts_builtin_sym_end] = ts_builtin_sym_end,
  [sym_comment] = sym_comment,
  [anon_sym_global] = anon_sym_global,
  [anon_sym_defaults] = anon_sym_defaults,
  [anon_sym_frontend] = anon_sym_frontend,
  [anon_sym_backend] = anon_sym_backend,
  [anon_sym_listen] = anon_sym_listen,
  [anon_sym_peers] = anon_sym_peers,
  [anon_sym_resolvers] = anon_sym_resolvers,
  [anon_sym_userlist] = anon_sym_userlist,
  [anon_sym_aggregations] = anon_sym_aggregations,
  [anon_sym_acl] = anon_sym_acl,
  [anon_sym_bind] = anon_sym_bind,
  [anon_sym_server] = anon_sym_server,
  [anon_sym_balance] = anon_sym_balance,
  [anon_sym_mode] = anon_sym_mode,
  [anon_sym_maxconn] = anon_sym_maxconn,
  [anon_sym_user] = anon_sym_user,
  [anon_sym_group] = anon_sym_group,
  [anon_sym_daemon] = anon_sym_daemon,
  [anon_sym_log] = anon_sym_log,
  [anon_sym_retries] = anon_sym_retries,
  [anon_sym_cookie] = anon_sym_cookie,
  [anon_sym_errorfile] = anon_sym_errorfile,
  [anon_sym_default_backend] = anon_sym_default_backend,
  [anon_sym_use_backend] = anon_sym_use_backend,
  [anon_sym_compression] = anon_sym_compression,
  [anon_sym_redirect] = anon_sym_redirect,
  [anon_sym_source] = anon_sym_source,
  [anon_sym_id] = anon_sym_id,
  [anon_sym_disabled] = anon_sym_disabled,
  [anon_sym_enabled] = anon_sym_enabled,
  [anon_sym_dispatch] = anon_sym_dispatch,
  [anon_sym_backlog] = anon_sym_backlog,
  [anon_sym_description] = anon_sym_description,
  [anon_sym_chroot] = anon_sym_chroot,
  [anon_sym_ca_DASHbase] = anon_sym_ca_DASHbase,
  [anon_sym_crt_DASHbase] = anon_sym_crt_DASHbase,
  [anon_sym_nbproc] = anon_sym_nbproc,
  [anon_sym_cpu_DASHmap] = anon_sym_cpu_DASHmap,
  [anon_sym_lua_DASHload] = anon_sym_lua_DASHload,
  [anon_sym_monitor_DASHnet] = anon_sym_monitor_DASHnet,
  [anon_sym_monitor_DASHuri] = anon_sym_monitor_DASHuri,
  [anon_sym_grace] = anon_sym_grace,
  [anon_sym_hash_DASHtype] = anon_sym_hash_DASHtype,
  [anon_sym_force_DASHpersist] = anon_sym_force_DASHpersist,
  [anon_sym_ignore_DASHpersist] = anon_sym_ignore_DASHpersist,
  [anon_sym_bind_DASHprocess] = anon_sym_bind_DASHprocess,
  [anon_sym_default_DASHserver] = anon_sym_default_DASHserver,
  [anon_sym_log_DASHformat] = anon_sym_log_DASHformat,
  [anon_sym_unique_DASHid_DASHformat] = anon_sym_unique_DASHid_DASHformat,
  [anon_sym_unique_DASHid_DASHheader] = anon_sym_unique_DASHid_DASHheader,
  [anon_sym_nameserver] = anon_sym_nameserver,
  [anon_sym_peer] = anon_sym_peer,
  [anon_sym_resolution_pool_size] = anon_sym_resolution_pool_size,
  [anon_sym_resolve_retries] = anon_sym_resolve_retries,
  [anon_sym_reqadd] = anon_sym_reqadd,
  [anon_sym_reqallow] = anon_sym_reqallow,
  [anon_sym_reqdel] = anon_sym_reqdel,
  [anon_sym_reqdeny] = anon_sym_reqdeny,
  [anon_sym_reqiallow] = anon_sym_reqiallow,
  [anon_sym_reqidel] = anon_sym_reqidel,
  [anon_sym_reqideny] = anon_sym_reqideny,
  [anon_sym_reqipass] = anon_sym_reqipass,
  [anon_sym_reqirep] = anon_sym_reqirep,
  [anon_sym_reqisetbe] = anon_sym_reqisetbe,
  [anon_sym_reqitarpit] = anon_sym_reqitarpit,
  [anon_sym_reqpass] = anon_sym_reqpass,
  [anon_sym_reqrep] = anon_sym_reqrep,
  [anon_sym_reqsetbe] = anon_sym_reqsetbe,
  [anon_sym_reqtarpit] = anon_sym_reqtarpit,
  [anon_sym_rspadd] = anon_sym_rspadd,
  [anon_sym_rspdel] = anon_sym_rspdel,
  [anon_sym_rspdeny] = anon_sym_rspdeny,
  [anon_sym_rspidel] = anon_sym_rspidel,
  [anon_sym_rspideny] = anon_sym_rspideny,
  [anon_sym_rspirep] = anon_sym_rspirep,
  [anon_sym_rsprep] = anon_sym_rsprep,
  [anon_sym_option] = anon_sym_option,
  [anon_sym_timeout] = anon_sym_timeout,
  [anon_sym_stats] = anon_sym_stats,
  [anon_sym_http_DASHrequest] = anon_sym_http_DASHrequest,
  [anon_sym_http_DASHresponse] = anon_sym_http_DASHresponse,
  [anon_sym_http_DASHcheck] = anon_sym_http_DASHcheck,
  [anon_sym_tcp_DASHrequest] = anon_sym_tcp_DASHrequest,
  [anon_sym_tcp_DASHresponse] = anon_sym_tcp_DASHresponse,
  [anon_sym_stick] = anon_sym_stick,
  [anon_sym_stick_DASHtable] = anon_sym_stick_DASHtable,
  [anon_sym_capture] = anon_sym_capture,
  [anon_sym_use_DASHserver] = anon_sym_use_DASHserver,
  [anon_sym_monitor] = anon_sym_monitor,
  [anon_sym_fail] = anon_sym_fail,
  [anon_sym_rate_DASHlimit] = anon_sym_rate_DASHlimit,
  [anon_sym_sessions] = anon_sym_sessions,
  [anon_sym_persist] = anon_sym_persist,
  [anon_sym_rdp_DASHcookie] = anon_sym_rdp_DASHcookie,
  [anon_sym_httplog] = anon_sym_httplog,
  [anon_sym_tcplog] = anon_sym_tcplog,
  [anon_sym_httpchk] = anon_sym_httpchk,
  [anon_sym_forwardfor] = anon_sym_forwardfor,
  [anon_sym_redispatch] = anon_sym_redispatch,
  [anon_sym_abortonclose] = anon_sym_abortonclose,
  [anon_sym_accept_DASHinvalid_DASHhttp_DASHrequest] = anon_sym_accept_DASHinvalid_DASHhttp_DASHrequest,
  [anon_sym_accept_DASHinvalid_DASHhttp_DASHresponse] = anon_sym_accept_DASHinvalid_DASHhttp_DASHresponse,
  [anon_sym_allbackups] = anon_sym_allbackups,
  [anon_sym_checkcache] = anon_sym_checkcache,
  [anon_sym_clitcpka] = anon_sym_clitcpka,
  [anon_sym_contstats] = anon_sym_contstats,
  [anon_sym_dontlog_DASHnormal] = anon_sym_dontlog_DASHnormal,
  [anon_sym_dontlognull] = anon_sym_dontlognull,
  [anon_sym_forceclose] = anon_sym_forceclose,
  [anon_sym_http_DASHno_DASHdelay] = anon_sym_http_DASHno_DASHdelay,
  [anon_sym_http_DASHpretend_DASHkeepalive] = anon_sym_http_DASHpretend_DASHkeepalive,
  [anon_sym_http_DASHserver_DASHclose] = anon_sym_http_DASHserver_DASHclose,
  [anon_sym_http_DASHuse_DASHproxy_DASHheader] = anon_sym_http_DASHuse_DASHproxy_DASHheader,
  [anon_sym_httpclose] = anon_sym_httpclose,
  [anon_sym_http_proxy] = anon_sym_http_proxy,
  [anon_sym_independent_DASHstreams] = anon_sym_independent_DASHstreams,
  [anon_sym_ldap_DASHcheck] = anon_sym_ldap_DASHcheck,
  [anon_sym_log_DASHhealth_DASHchecks] = anon_sym_log_DASHhealth_DASHchecks,
  [anon_sym_log_DASHseparate_DASHerrors] = anon_sym_log_DASHseparate_DASHerrors,
  [anon_sym_logasap] = anon_sym_logasap,
  [anon_sym_mysql_DASHcheck] = anon_sym_mysql_DASHcheck,
  [anon_sym_pgsql_DASHcheck] = anon_sym_pgsql_DASHcheck,
  [anon_sym_nolinger] = anon_sym_nolinger,
  [anon_sym_originalto] = anon_sym_originalto,
  [anon_sym_redis_DASHcheck] = anon_sym_redis_DASHcheck,
  [anon_sym_smtpchk] = anon_sym_smtpchk,
  [anon_sym_socket_DASHstats] = anon_sym_socket_DASHstats,
  [anon_sym_splice_DASHauto] = anon_sym_splice_DASHauto,
  [anon_sym_splice_DASHrequest] = anon_sym_splice_DASHrequest,
  [anon_sym_splice_DASHresponse] = anon_sym_splice_DASHresponse,
  [anon_sym_srvtcpka] = anon_sym_srvtcpka,
  [anon_sym_ssl_DASHhello_DASHchk] = anon_sym_ssl_DASHhello_DASHchk,
  [anon_sym_tcp_DASHcheck] = anon_sym_tcp_DASHcheck,
  [anon_sym_tcp_DASHsmart_DASHaccept] = anon_sym_tcp_DASHsmart_DASHaccept,
  [anon_sym_tcp_DASHsmart_DASHconnect] = anon_sym_tcp_DASHsmart_DASHconnect,
  [anon_sym_tcpka] = anon_sym_tcpka,
  [anon_sym_transparent] = anon_sym_transparent,
  [anon_sym_check] = anon_sym_check,
  [anon_sym_client] = anon_sym_client,
  [anon_sym_connect] = anon_sym_connect,
  [anon_sym_http_DASHkeep_DASHalive] = anon_sym_http_DASHkeep_DASHalive,
  [anon_sym_queue] = anon_sym_queue,
  [anon_sym_tarpit] = anon_sym_tarpit,
  [anon_sym_tunnel] = anon_sym_tunnel,
  [anon_sym_enable] = anon_sym_enable,
  [anon_sym_uri] = anon_sym_uri,
  [anon_sym_realm] = anon_sym_realm,
  [anon_sym_auth] = anon_sym_auth,
  [anon_sym_refresh] = anon_sym_refresh,
  [anon_sym_admin] = anon_sym_admin,
  [anon_sym_hide_DASHversion] = anon_sym_hide_DASHversion,
  [anon_sym_show_DASHdesc] = anon_sym_show_DASHdesc,
  [anon_sym_show_DASHlegends] = anon_sym_show_DASHlegends,
  [anon_sym_show_DASHnode] = anon_sym_show_DASHnode,
  [anon_sym_socket] = anon_sym_socket,
  [anon_sym_scope] = anon_sym_scope,
  [anon_sym_add_DASHheader] = anon_sym_add_DASHheader,
  [anon_sym_set_DASHheader] = anon_sym_set_DASHheader,
  [anon_sym_del_DASHheader] = anon_sym_del_DASHheader,
  [anon_sym_replace_DASHheader] = anon_sym_replace_DASHheader,
  [anon_sym_replace_DASHvalue] = anon_sym_replace_DASHvalue,
  [anon_sym_deny] = anon_sym_deny,
  [anon_sym_allow] = anon_sym_allow,
  [anon_sym_set_DASHlog_DASHlevel] = anon_sym_set_DASHlog_DASHlevel,
  [anon_sym_set_DASHnice] = anon_sym_set_DASHnice,
  [anon_sym_set_DASHtos] = anon_sym_set_DASHtos,
  [anon_sym_set_DASHmark] = anon_sym_set_DASHmark,
  [anon_sym_add_DASHacl] = anon_sym_add_DASHacl,
  [anon_sym_del_DASHacl] = anon_sym_del_DASHacl,
  [anon_sym_set_DASHmap] = anon_sym_set_DASHmap,
  [anon_sym_del_DASHmap] = anon_sym_del_DASHmap,
  [anon_sym_disable_DASHon_DASH404] = anon_sym_disable_DASHon_DASH404,
  [anon_sym_expect] = anon_sym_expect,
  [anon_sym_send_DASHstate] = anon_sym_send_DASHstate,
  [anon_sym_connection] = anon_sym_connection,
  [anon_sym_content] = anon_sym_content,
  [anon_sym_inspect_DASHdelay] = anon_sym_inspect_DASHdelay,
  [anon_sym_match] = anon_sym_match,
  [anon_sym_on] = anon_sym_on,
  [anon_sym_store_DASHrequest] = anon_sym_store_DASHrequest,
  [anon_sym_store_DASHresponse] = anon_sym_store_DASHresponse,
  [anon_sym_request] = anon_sym_request,
  [anon_sym_header] = anon_sym_header,
  [anon_sym_response] = anon_sym_response,
  [sym_string] = sym_string,
  [sym_ip_address] = sym_ip_address,
  [sym_wildcard_bind] = sym_wildcard_bind,
  [sym_number] = sym_number,
  [sym_time_value] = sym_time_value,
  [sym_parameter] = sym_parameter,
  [anon_sym_or] = anon_sym_or,
  [anon_sym_PIPE_PIPE] = anon_sym_PIPE_PIPE,
  [anon_sym_BANG] = anon_sym_BANG,
  [anon_sym_if] = anon_sym_if,
  [anon_sym_unless] = anon_sym_unless,
  [anon_sym_rewrite] = anon_sym_rewrite,
  [sym_identifier] = sym_identifier,
  [sym_path] = sym_path,
  [sym_source_file] = sym_source_file,
  [sym__statement] = sym__statement,
  [sym_section] = sym_section,
  [sym_section_name] = sym_section_name,
  [sym_directive] = sym_directive,
  [sym_keyword] = sym_keyword,
  [sym_keyword_combination] = sym_keyword_combination,
  [sym_option_value] = sym_option_value,
  [sym_timeout_type] = sym_timeout_type,
  [sym_stats_option] = sym_stats_option,
  [sym_http_action] = sym_http_action,
  [sym_http_check_option] = sym_http_check_option,
  [sym_tcp_request_type] = sym_tcp_request_type,
  [sym_tcp_response_type] = sym_tcp_response_type,
  [sym_stick_option] = sym_stick_option,
  [sym_capture_type] = sym_capture_type,
  [sym_arguments] = sym_arguments,
  [sym__argument] = sym__argument,
  [sym_operator] = sym_operator,
  [sym_control_flow] = sym_control_flow,
  [aux_sym_source_file_repeat1] = aux_sym_source_file_repeat1,
  [aux_sym_section_repeat1] = aux_sym_section_repeat1,
  [aux_sym_arguments_repeat1] = aux_sym_arguments_repeat1,
};

static const TSSymbolMetadata ts_symbol_metadata[] = {
  [ts_builtin_sym_end] = {
    .visible = false,
    .named = true,
  },
  [sym_comment] = {
    .visible = true,
    .named = true,
  },
  [anon_sym_global] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_defaults] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_frontend] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_backend] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_listen] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_peers] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_resolvers] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_userlist] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_aggregations] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_acl] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_bind] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_server] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_balance] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_mode] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_maxconn] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_user] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_group] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_daemon] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_log] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_retries] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cookie] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_errorfile] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_default_backend] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_use_backend] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_compression] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_redirect] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_source] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_id] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_disabled] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_enabled] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_dispatch] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_backlog] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_description] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_chroot] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ca_DASHbase] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_crt_DASHbase] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_nbproc] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cpu_DASHmap] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_lua_DASHload] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_monitor_DASHnet] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_monitor_DASHuri] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_grace] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_hash_DASHtype] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_force_DASHpersist] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ignore_DASHpersist] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_bind_DASHprocess] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_default_DASHserver] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_log_DASHformat] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_unique_DASHid_DASHformat] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_unique_DASHid_DASHheader] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_nameserver] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_peer] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_resolution_pool_size] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_resolve_retries] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_reqadd] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_reqallow] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_reqdel] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_reqdeny] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_reqiallow] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_reqidel] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_reqideny] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_reqipass] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_reqirep] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_reqisetbe] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_reqitarpit] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_reqpass] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_reqrep] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_reqsetbe] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_reqtarpit] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_rspadd] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_rspdel] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_rspdeny] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_rspidel] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_rspideny] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_rspirep] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_rsprep] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_option] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_timeout] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_stats] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DASHrequest] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DASHresponse] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DASHcheck] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DASHrequest] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DASHresponse] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_stick] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_stick_DASHtable] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_capture] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_use_DASHserver] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_monitor] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_fail] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_rate_DASHlimit] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_sessions] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_persist] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_rdp_DASHcookie] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_httplog] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcplog] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_httpchk] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_forwardfor] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_redispatch] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_abortonclose] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_accept_DASHinvalid_DASHhttp_DASHrequest] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_accept_DASHinvalid_DASHhttp_DASHresponse] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_allbackups] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_checkcache] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_clitcpka] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_contstats] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_dontlog_DASHnormal] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_dontlognull] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_forceclose] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DASHno_DASHdelay] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DASHpretend_DASHkeepalive] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DASHserver_DASHclose] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DASHuse_DASHproxy_DASHheader] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_httpclose] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_proxy] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_independent_DASHstreams] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ldap_DASHcheck] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_log_DASHhealth_DASHchecks] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_log_DASHseparate_DASHerrors] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_logasap] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_mysql_DASHcheck] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_pgsql_DASHcheck] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_nolinger] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_originalto] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_redis_DASHcheck] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_smtpchk] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_socket_DASHstats] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_splice_DASHauto] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_splice_DASHrequest] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_splice_DASHresponse] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_srvtcpka] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ssl_DASHhello_DASHchk] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DASHcheck] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DASHsmart_DASHaccept] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DASHsmart_DASHconnect] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcpka] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_transparent] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_check] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_client] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_connect] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DASHkeep_DASHalive] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_queue] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tarpit] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tunnel] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_enable] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_uri] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_realm] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_auth] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_refresh] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_admin] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_hide_DASHversion] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_show_DASHdesc] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_show_DASHlegends] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_show_DASHnode] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_socket] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_scope] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_add_DASHheader] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_set_DASHheader] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_del_DASHheader] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_replace_DASHheader] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_replace_DASHvalue] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_deny] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_allow] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_set_DASHlog_DASHlevel] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_set_DASHnice] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_set_DASHtos] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_set_DASHmark] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_add_DASHacl] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_del_DASHacl] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_set_DASHmap] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_del_DASHmap] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_disable_DASHon_DASH404] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_expect] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_send_DASHstate] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_connection] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_content] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_inspect_DASHdelay] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_match] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_on] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_store_DASHrequest] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_store_DASHresponse] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_request] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_header] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_response] = {
    .visible = true,
    .named = false,
  },
  [sym_string] = {
    .visible = true,
    .named = true,
  },
  [sym_ip_address] = {
    .visible = true,
    .named = true,
  },
  [sym_wildcard_bind] = {
    .visible = true,
    .named = true,
  },
  [sym_number] = {
    .visible = true,
    .named = true,
  },
  [sym_time_value] = {
    .visible = true,
    .named = true,
  },
  [sym_parameter] = {
    .visible = true,
    .named = true,
  },
  [anon_sym_or] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_PIPE_PIPE] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_BANG] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_if] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_unless] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_rewrite] = {
    .visible = true,
    .named = false,
  },
  [sym_identifier] = {
    .visible = true,
    .named = true,
  },
  [sym_path] = {
    .visible = true,
    .named = true,
  },
  [sym_source_file] = {
    .visible = true,
    .named = true,
  },
  [sym__statement] = {
    .visible = false,
    .named = true,
  },
  [sym_section] = {
    .visible = true,
    .named = true,
  },
  [sym_section_name] = {
    .visible = true,
    .named = true,
  },
  [sym_directive] = {
    .visible = true,
    .named = true,
  },
  [sym_keyword] = {
    .visible = true,
    .named = true,
  },
  [sym_keyword_combination] = {
    .visible = true,
    .named = true,
  },
  [sym_option_value] = {
    .visible = true,
    .named = true,
  },
  [sym_timeout_type] = {
    .visible = true,
    .named = true,
  },
  [sym_stats_option] = {
    .visible = true,
    .named = true,
  },
  [sym_http_action] = {
    .visible = true,
    .named = true,
  },
  [sym_http_check_option] = {
    .visible = true,
    .named = true,
  },
  [sym_tcp_request_type] = {
    .visible = true,
    .named = true,
  },
  [sym_tcp_response_type] = {
    .visible = true,
    .named = true,
  },
  [sym_stick_option] = {
    .visible = true,
    .named = true,
  },
  [sym_capture_type] = {
    .visible = true,
    .named = true,
  },
  [sym_arguments] = {
    .visible = true,
    .named = true,
  },
  [sym__argument] = {
    .visible = false,
    .named = true,
  },
  [sym_operator] = {
    .visible = true,
    .named = true,
  },
  [sym_control_flow] = {
    .visible = true,
    .named = true,
  },
  [aux_sym_source_file_repeat1] = {
    .visible = false,
    .named = false,
  },
  [aux_sym_section_repeat1] = {
    .visible = false,
    .named = false,
  },
  [aux_sym_arguments_repeat1] = {
    .visible = false,
    .named = false,
  },
};

enum {
  field_args = 1,
  field_keyword = 2,
  field_name = 3,
  field_type = 4,
};

static const char * const ts_field_names[] = {
  [0] = NULL,
  [field_args] = "args",
  [field_keyword] = "keyword",
  [field_name] = "name",
  [field_type] = "type",
};

static const TSFieldMapSlice ts_field_map_slices[PRODUCTION_ID_COUNT] = {
  [1] = {.index = 0, .length = 1},
  [2] = {.index = 1, .length = 1},
  [3] = {.index = 2, .length = 2},
  [4] = {.index = 4, .length = 2},
};

static const TSFieldMapEntry ts_field_map_entries[] = {
  [0] =
    {field_type, 0},
  [1] =
    {field_keyword, 0},
  [2] =
    {field_name, 1},
    {field_type, 0},
  [4] =
    {field_args, 1},
    {field_keyword, 0},
};

static const TSSymbol ts_alias_sequences[PRODUCTION_ID_COUNT][MAX_ALIAS_SEQUENCE_LENGTH] = {
  [0] = {0},
};

static const uint16_t ts_non_terminal_alias_map[] = {
  0,
};

static const TSStateId ts_primary_state_ids[STATE_COUNT] = {
  [0] = 0,
  [1] = 1,
  [2] = 2,
  [3] = 3,
  [4] = 4,
  [5] = 3,
  [6] = 6,
  [7] = 7,
  [8] = 8,
  [9] = 9,
  [10] = 10,
  [11] = 11,
  [12] = 12,
  [13] = 13,
  [14] = 14,
  [15] = 15,
  [16] = 16,
  [17] = 17,
  [18] = 18,
  [19] = 19,
  [20] = 20,
  [21] = 21,
  [22] = 22,
  [23] = 23,
  [24] = 24,
  [25] = 25,
  [26] = 26,
  [27] = 27,
  [28] = 28,
  [29] = 29,
  [30] = 30,
  [31] = 31,
  [32] = 32,
  [33] = 33,
  [34] = 34,
  [35] = 35,
  [36] = 36,
  [37] = 37,
  [38] = 38,
  [39] = 39,
  [40] = 40,
  [41] = 41,
  [42] = 42,
  [43] = 43,
  [44] = 44,
  [45] = 45,
};

static bool ts_lex(TSLexer *lexer, TSStateId state) {
  START_LEXER();
  eof = lexer->eof(lexer);
  switch (state) {
    case 0:
      if (eof) ADVANCE(1140);
      if (lookahead == '!') ADVANCE(1442);
      if (lookahead == '"') ADVANCE(2);
      if (lookahead == '#') ADVANCE(1141);
      if (lookahead == '%') ADVANCE(84);
      if (lookahead == '*') ADVANCE(79);
      if (lookahead == '/') ADVANCE(1905);
      if (lookahead == '2') ADVANCE(1430);
      if (lookahead == 'a') ADVANCE(177);
      if (lookahead == 'b') ADVANCE(102);
      if (lookahead == 'c') ADVANCE(89);
      if (lookahead == 'd') ADVANCE(91);
      if (lookahead == 'e') ADVANCE(670);
      if (lookahead == 'f') ADVANCE(103);
      if (lookahead == 'g') ADVANCE(617);
      if (lookahead == 'h') ADVANCE(104);
      if (lookahead == 'i') ADVANCE(263);
      if (lookahead == 'l') ADVANCE(277);
      if (lookahead == 'm') ADVANCE(93);
      if (lookahead == 'n') ADVANCE(95);
      if (lookahead == 'o') ADVANCE(671);
      if (lookahead == 'p') ADVANCE(352);
      if (lookahead == 'q') ADVANCE(1084);
      if (lookahead == 'r') ADVANCE(114);
      if (lookahead == 's') ADVANCE(198);
      if (lookahead == 't') ADVANCE(108);
      if (lookahead == 'u') ADVANCE(672);
      if (lookahead == '|') ADVANCE(1133);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(1434);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(0)
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(1433);
      END_STATE();
    case 1:
      if (lookahead == '!') ADVANCE(1442);
      if (lookahead == '"') ADVANCE(2);
      if (lookahead == '#') ADVANCE(1141);
      if (lookahead == '%') ADVANCE(84);
      if (lookahead == '*') ADVANCE(79);
      if (lookahead == '/') ADVANCE(1905);
      if (lookahead == '2') ADVANCE(1430);
      if (lookahead == 'i') ADVANCE(1621);
      if (lookahead == 'o') ADVANCE(1773);
      if (lookahead == 'r') ADVANCE(1576);
      if (lookahead == 'u') ADVANCE(1716);
      if (lookahead == '|') ADVANCE(1133);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(1434);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(1)
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(1433);
      if (('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 2:
      if (lookahead == '"') ADVANCE(1419);
      if (lookahead != 0) ADVANCE(2);
      END_STATE();
    case 3:
      if (lookahead == '#') ADVANCE(1141);
      if (lookahead == 'a') ADVANCE(178);
      if (lookahead == 'c') ADVANCE(519);
      if (lookahead == 'd') ADVANCE(734);
      if (lookahead == 'f') ADVANCE(773);
      if (lookahead == 'h') ADVANCE(1064);
      if (lookahead == 'i') ADVANCE(723);
      if (lookahead == 'l') ADVANCE(278);
      if (lookahead == 'm') ADVANCE(1129);
      if (lookahead == 'n') ADVANCE(733);
      if (lookahead == 'o') ADVANCE(888);
      if (lookahead == 'p') ADVANCE(470);
      if (lookahead == 'r') ADVANCE(379);
      if (lookahead == 's') ADVANCE(663);
      if (lookahead == 't') ADVANCE(224);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(3)
      END_STATE();
    case 4:
      if (lookahead == '#') ADVANCE(1141);
      if (lookahead == 'a') ADVANCE(285);
      if (lookahead == 'b') ADVANCE(564);
      if (lookahead == 'e') ADVANCE(669);
      if (lookahead == 'h') ADVANCE(524);
      if (lookahead == 'r') ADVANCE(350);
      if (lookahead == 's') ADVANCE(199);
      if (lookahead == 't') ADVANCE(552);
      if (lookahead == 'u') ADVANCE(876);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(4)
      END_STATE();
    case 5:
      if (lookahead == '-') ADVANCE(182);
      if (lookahead == 'p') ADVANCE(1036);
      END_STATE();
    case 6:
      if (lookahead == '-') ADVANCE(125);
      END_STATE();
    case 7:
      if (lookahead == '-') ADVANCE(149);
      END_STATE();
    case 8:
      if (lookahead == '-') ADVANCE(520);
      END_STATE();
    case 9:
      if (lookahead == '-') ADVANCE(232);
      if (lookahead == 'k') ADVANCE(98);
      if (lookahead == 'l') ADVANCE(738);
      END_STATE();
    case 10:
      if (lookahead == '-') ADVANCE(250);
      if (lookahead == '_') ADVANCE(832);
      if (lookahead == 'c') ADVANCE(504);
      if (lookahead == 'l') ADVANCE(743);
      END_STATE();
    case 11:
      if (lookahead == '-') ADVANCE(295);
      END_STATE();
    case 12:
      if (lookahead == '-') ADVANCE(145);
      END_STATE();
    case 13:
      if (lookahead == '-') ADVANCE(521);
      END_STATE();
    case 14:
      if (lookahead == '-') ADVANCE(133);
      END_STATE();
    case 15:
      if (lookahead == '-') ADVANCE(485);
      END_STATE();
    case 16:
      if (lookahead == '-') ADVANCE(76);
      END_STATE();
    case 17:
      if (lookahead == '-') ADVANCE(251);
      END_STATE();
    case 18:
      if (lookahead == '-') ADVANCE(508);
      if (lookahead == 'a') ADVANCE(988);
      END_STATE();
    case 19:
      if (lookahead == '-') ADVANCE(233);
      if (lookahead == 'k') ADVANCE(98);
      if (lookahead == 'l') ADVANCE(738);
      END_STATE();
    case 20:
      if (lookahead == '-') ADVANCE(698);
      if (lookahead == '_') ADVANCE(832);
      if (lookahead == 'c') ADVANCE(504);
      if (lookahead == 'l') ADVANCE(743);
      END_STATE();
    case 21:
      if (lookahead == '-') ADVANCE(664);
      END_STATE();
    case 22:
      if (lookahead == '-') ADVANCE(509);
      END_STATE();
    case 23:
      if (lookahead == '-') ADVANCE(235);
      END_STATE();
    case 24:
      if (lookahead == '-') ADVANCE(510);
      END_STATE();
    case 25:
      if (lookahead == '-') ADVANCE(252);
      END_STATE();
    case 26:
      if (lookahead == '-') ADVANCE(554);
      END_STATE();
    case 27:
      if (lookahead == '-') ADVANCE(1033);
      END_STATE();
    case 28:
      if (lookahead == '-') ADVANCE(409);
      END_STATE();
    case 29:
      if (lookahead == '-') ADVANCE(1106);
      END_STATE();
    case 30:
      if (lookahead == '-') ADVANCE(624);
      END_STATE();
    case 31:
      if (lookahead == '-') ADVANCE(234);
      END_STATE();
    case 32:
      if (lookahead == '-') ADVANCE(622);
      END_STATE();
    case 33:
      if (lookahead == '-') ADVANCE(594);
      END_STATE();
    case 34:
      if (lookahead == '-') ADVANCE(539);
      END_STATE();
    case 35:
      if (lookahead == '-') ADVANCE(523);
      END_STATE();
    case 36:
      if (lookahead == '-') ADVANCE(829);
      END_STATE();
    case 37:
      if (lookahead == '-') ADVANCE(829);
      if (lookahead == 'c') ADVANCE(648);
      END_STATE();
    case 38:
      if (lookahead == '-') ADVANCE(964);
      END_STATE();
    case 39:
      if (lookahead == '-') ADVANCE(637);
      END_STATE();
    case 40:
      if (lookahead == '-') ADVANCE(992);
      END_STATE();
    case 41:
      if (lookahead == '-') ADVANCE(928);
      END_STATE();
    case 42:
      if (lookahead == '-') ADVANCE(301);
      END_STATE();
    case 43:
      if (lookahead == '-') ADVANCE(756);
      if (lookahead == 'd') ADVANCE(1199);
      END_STATE();
    case 44:
      if (lookahead == '-') ADVANCE(899);
      END_STATE();
    case 45:
      if (lookahead == '-') ADVANCE(973);
      END_STATE();
    case 46:
      if (lookahead == '-') ADVANCE(826);
      END_STATE();
    case 47:
      if (lookahead == '-') ADVANCE(726);
      if (lookahead == 'n') ADVANCE(1089);
      END_STATE();
    case 48:
      if (lookahead == '-') ADVANCE(157);
      END_STATE();
    case 49:
      if (lookahead == '-') ADVANCE(305);
      END_STATE();
    case 50:
      if (lookahead == '-') ADVANCE(835);
      END_STATE();
    case 51:
      if (lookahead == '-') ADVANCE(191);
      END_STATE();
    case 52:
      if (lookahead == '-') ADVANCE(993);
      if (lookahead == '_') ADVANCE(190);
      if (lookahead == 'r') ADVANCE(1173);
      END_STATE();
    case 53:
      if (lookahead == '-') ADVANCE(253);
      END_STATE();
    case 54:
      if (lookahead == '-') ADVANCE(996);
      if (lookahead == '_') ADVANCE(192);
      if (lookahead == 's') ADVANCE(1144);
      END_STATE();
    case 55:
      if (lookahead == '-') ADVANCE(254);
      END_STATE();
    case 56:
      if (lookahead == '-') ADVANCE(255);
      if (lookahead == 'p') ADVANCE(140);
      END_STATE();
    case 57:
      if (lookahead == '-') ADVANCE(256);
      END_STATE();
    case 58:
      if (lookahead == '-') ADVANCE(259);
      END_STATE();
    case 59:
      if (lookahead == '-') ADVANCE(846);
      END_STATE();
    case 60:
      if (lookahead == '-') ADVANCE(893);
      END_STATE();
    case 61:
      if (lookahead == '-') ADVANCE(929);
      END_STATE();
    case 62:
      if (lookahead == '.') ADVANCE(74);
      END_STATE();
    case 63:
      if (lookahead == '.') ADVANCE(74);
      if (lookahead == '5') ADVANCE(64);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(62);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(65);
      END_STATE();
    case 64:
      if (lookahead == '.') ADVANCE(74);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(62);
      END_STATE();
    case 65:
      if (lookahead == '.') ADVANCE(74);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(62);
      END_STATE();
    case 66:
      if (lookahead == '.') ADVANCE(74);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(65);
      END_STATE();
    case 67:
      if (lookahead == '.') ADVANCE(75);
      END_STATE();
    case 68:
      if (lookahead == '.') ADVANCE(75);
      if (lookahead == '5') ADVANCE(69);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(67);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(70);
      END_STATE();
    case 69:
      if (lookahead == '.') ADVANCE(75);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(67);
      END_STATE();
    case 70:
      if (lookahead == '.') ADVANCE(75);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(67);
      END_STATE();
    case 71:
      if (lookahead == '.') ADVANCE(75);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(70);
      END_STATE();
    case 72:
      if (lookahead == '0') ADVANCE(77);
      END_STATE();
    case 73:
      if (lookahead == '2') ADVANCE(68);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(71);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(70);
      END_STATE();
    case 74:
      if (lookahead == '2') ADVANCE(78);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(82);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(83);
      END_STATE();
    case 75:
      if (lookahead == '2') ADVANCE(63);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(66);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(65);
      END_STATE();
    case 76:
      if (lookahead == '4') ADVANCE(72);
      END_STATE();
    case 77:
      if (lookahead == '4') ADVANCE(1406);
      END_STATE();
    case 78:
      if (lookahead == '5') ADVANCE(81);
      if (lookahead == ':') ADVANCE(1135);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(80);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(83);
      END_STATE();
    case 79:
      if (lookahead == ':') ADVANCE(1134);
      END_STATE();
    case 80:
      if (lookahead == ':') ADVANCE(1135);
      END_STATE();
    case 81:
      if (lookahead == ':') ADVANCE(1135);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(80);
      END_STATE();
    case 82:
      if (lookahead == ':') ADVANCE(1135);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(83);
      END_STATE();
    case 83:
      if (lookahead == ':') ADVANCE(1135);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(80);
      END_STATE();
    case 84:
      if (lookahead == '[') ADVANCE(1136);
      END_STATE();
    case 85:
      if (lookahead == ']') ADVANCE(1438);
      if (lookahead != 0) ADVANCE(85);
      END_STATE();
    case 86:
      if (lookahead == '_') ADVANCE(831);
      END_STATE();
    case 87:
      if (lookahead == '_') ADVANCE(959);
      END_STATE();
    case 88:
      if (lookahead == '_') ADVANCE(897);
      if (lookahead == 'r') ADVANCE(940);
      END_STATE();
    case 89:
      if (lookahead == 'a') ADVANCE(5);
      if (lookahead == 'h') ADVANCE(307);
      if (lookahead == 'l') ADVANCE(525);
      if (lookahead == 'o') ADVANCE(661);
      if (lookahead == 'p') ADVANCE(1085);
      if (lookahead == 'r') ADVANCE(1034);
      END_STATE();
    case 90:
      if (lookahead == 'a') ADVANCE(5);
      if (lookahead == 'h') ADVANCE(878);
      if (lookahead == 'o') ADVANCE(662);
      if (lookahead == 'p') ADVANCE(1085);
      if (lookahead == 'r') ADVANCE(1034);
      END_STATE();
    case 91:
      if (lookahead == 'a') ADVANCE(353);
      if (lookahead == 'e') ADVANCE(479);
      if (lookahead == 'i') ADVANCE(930);
      if (lookahead == 'o') ADVANCE(688);
      END_STATE();
    case 92:
      if (lookahead == 'a') ADVANCE(353);
      if (lookahead == 'e') ADVANCE(480);
      if (lookahead == 'i') ADVANCE(999);
      END_STATE();
    case 93:
      if (lookahead == 'a') ADVANCE(1037);
      if (lookahead == 'o') ADVANCE(284);
      if (lookahead == 'y') ADVANCE(931);
      END_STATE();
    case 94:
      if (lookahead == 'a') ADVANCE(656);
      if (lookahead == 'b') ADVANCE(812);
      END_STATE();
    case 95:
      if (lookahead == 'a') ADVANCE(656);
      if (lookahead == 'b') ADVANCE(812);
      if (lookahead == 'o') ADVANCE(642);
      END_STATE();
    case 96:
      if (lookahead == 'a') ADVANCE(279);
      if (lookahead == 'd') ADVANCE(313);
      if (lookahead == 'i') ADVANCE(128);
      if (lookahead == 'p') ADVANCE(147);
      if (lookahead == 'r') ADVANCE(370);
      if (lookahead == 's') ADVANCE(384);
      if (lookahead == 't') ADVANCE(173);
      END_STATE();
    case 97:
      if (lookahead == 'a') ADVANCE(279);
      if (lookahead == 'd') ADVANCE(313);
      if (lookahead == 'i') ADVANCE(128);
      if (lookahead == 'p') ADVANCE(147);
      if (lookahead == 'r') ADVANCE(370);
      if (lookahead == 's') ADVANCE(384);
      if (lookahead == 't') ADVANCE(173);
      if (lookahead == 'u') ADVANCE(430);
      END_STATE();
    case 98:
      if (lookahead == 'a') ADVANCE(1369);
      END_STATE();
    case 99:
      if (lookahead == 'a') ADVANCE(806);
      END_STATE();
    case 100:
      if (lookahead == 'a') ADVANCE(1338);
      END_STATE();
    case 101:
      if (lookahead == 'a') ADVANCE(1364);
      END_STATE();
    case 102:
      if (lookahead == 'a') ADVANCE(193);
      if (lookahead == 'i') ADVANCE(683);
      END_STATE();
    case 103:
      if (lookahead == 'a') ADVANCE(533);
      if (lookahead == 'o') ADVANCE(858);
      if (lookahead == 'r') ADVANCE(772);
      END_STATE();
    case 104:
      if (lookahead == 'a') ADVANCE(951);
      if (lookahead == 'e') ADVANCE(144);
      if (lookahead == 'i') ADVANCE(280);
      if (lookahead == 't') ADVANCE(1039);
      END_STATE();
    case 105:
      if (lookahead == 'a') ADVANCE(951);
      if (lookahead == 't') ADVANCE(1065);
      END_STATE();
    case 106:
      if (lookahead == 'a') ADVANCE(179);
      END_STATE();
    case 107:
      if (lookahead == 'a') ADVANCE(1118);
      if (lookahead == 'o') ADVANCE(284);
      END_STATE();
    case 108:
      if (lookahead == 'a') ADVANCE(880);
      if (lookahead == 'c') ADVANCE(797);
      if (lookahead == 'i') ADVANCE(657);
      if (lookahead == 'r') ADVANCE(116);
      if (lookahead == 'u') ADVANCE(687);
      END_STATE();
    case 109:
      if (lookahead == 'a') ADVANCE(214);
      if (lookahead == 'o') ADVANCE(1088);
      END_STATE();
    case 110:
      if (lookahead == 'a') ADVANCE(281);
      if (lookahead == 'd') ADVANCE(354);
      if (lookahead == 'i') ADVANCE(294);
      if (lookahead == 'r') ADVANCE(373);
      END_STATE();
    case 111:
      if (lookahead == 'a') ADVANCE(1087);
      END_STATE();
    case 112:
      if (lookahead == 'a') ADVANCE(618);
      if (lookahead == 'd') ADVANCE(527);
      if (lookahead == 'f') ADVANCE(887);
      if (lookahead == 'p') ADVANCE(623);
      if (lookahead == 'q') ADVANCE(97);
      if (lookahead == 's') ADVANCE(746);
      if (lookahead == 't') ADVANCE(904);
      if (lookahead == 'w') ADVANCE(883);
      END_STATE();
    case 113:
      if (lookahead == 'a') ADVANCE(618);
      if (lookahead == 'f') ADVANCE(887);
      END_STATE();
    case 114:
      if (lookahead == 'a') ADVANCE(1060);
      if (lookahead == 'd') ADVANCE(813);
      if (lookahead == 'e') ADVANCE(112);
      if (lookahead == 's') ADVANCE(796);
      END_STATE();
    case 115:
      if (lookahead == 'a') ADVANCE(1060);
      if (lookahead == 'e') ADVANCE(288);
      if (lookahead == 's') ADVANCE(796);
      END_STATE();
    case 116:
      if (lookahead == 'a') ADVANCE(690);
      END_STATE();
    case 117:
      if (lookahead == 'a') ADVANCE(30);
      END_STATE();
    case 118:
      if (lookahead == 'a') ADVANCE(658);
      END_STATE();
    case 119:
      if (lookahead == 'a') ADVANCE(714);
      END_STATE();
    case 120:
      if (lookahead == 'a') ADVANCE(1127);
      END_STATE();
    case 121:
      if (lookahead == 'a') ADVANCE(1042);
      if (lookahead == 'i') ADVANCE(204);
      END_STATE();
    case 122:
      if (lookahead == 'a') ADVANCE(1042);
      if (lookahead == 'i') ADVANCE(204);
      if (lookahead == 'o') ADVANCE(909);
      END_STATE();
    case 123:
      if (lookahead == 'a') ADVANCE(1128);
      END_STATE();
    case 124:
      if (lookahead == 'a') ADVANCE(272);
      END_STATE();
    case 125:
      if (lookahead == 'a') ADVANCE(213);
      if (lookahead == 'h') ADVANCE(458);
      END_STATE();
    case 126:
      if (lookahead == 'a') ADVANCE(605);
      END_STATE();
    case 127:
      if (lookahead == 'a') ADVANCE(881);
      END_STATE();
    case 128:
      if (lookahead == 'a') ADVANCE(644);
      if (lookahead == 'd') ADVANCE(356);
      if (lookahead == 'p') ADVANCE(153);
      if (lookahead == 'r') ADVANCE(391);
      if (lookahead == 's') ADVANCE(426);
      if (lookahead == 't') ADVANCE(175);
      END_STATE();
    case 129:
      if (lookahead == 'a') ADVANCE(1044);
      END_STATE();
    case 130:
      if (lookahead == 'a') ADVANCE(802);
      END_STATE();
    case 131:
      if (lookahead == 'a') ADVANCE(641);
      END_STATE();
    case 132:
      if (lookahead == 'a') ADVANCE(803);
      END_STATE();
    case 133:
      if (lookahead == 'a') ADVANCE(247);
      if (lookahead == 'c') ADVANCE(776);
      END_STATE();
    case 134:
      if (lookahead == 'a') ADVANCE(643);
      END_STATE();
    case 135:
      if (lookahead == 'a') ADVANCE(910);
      END_STATE();
    case 136:
      if (lookahead == 'a') ADVANCE(906);
      END_STATE();
    case 137:
      if (lookahead == 'a') ADVANCE(615);
      END_STATE();
    case 138:
      if (lookahead == 'a') ADVANCE(807);
      END_STATE();
    case 139:
      if (lookahead == 'a') ADVANCE(1048);
      END_STATE();
    case 140:
      if (lookahead == 'a') ADVANCE(1047);
      END_STATE();
    case 141:
      if (lookahead == 'a') ADVANCE(1017);
      END_STATE();
    case 142:
      if (lookahead == 'a') ADVANCE(1051);
      END_STATE();
    case 143:
      if (lookahead == 'a') ADVANCE(1029);
      END_STATE();
    case 144:
      if (lookahead == 'a') ADVANCE(287);
      END_STATE();
    case 145:
      if (lookahead == 'a') ADVANCE(1093);
      if (lookahead == 'r') ADVANCE(476);
      END_STATE();
    case 146:
      if (lookahead == 'a') ADVANCE(968);
      END_STATE();
    case 147:
      if (lookahead == 'a') ADVANCE(955);
      END_STATE();
    case 148:
      if (lookahead == 'a') ADVANCE(635);
      END_STATE();
    case 149:
      if (lookahead == 'a') ADVANCE(216);
      if (lookahead == 'h') ADVANCE(463);
      if (lookahead == 'm') ADVANCE(132);
      END_STATE();
    case 150:
      if (lookahead == 'a') ADVANCE(296);
      END_STATE();
    case 151:
      if (lookahead == 'a') ADVANCE(205);
      END_STATE();
    case 152:
      if (lookahead == 'a') ADVANCE(975);
      END_STATE();
    case 153:
      if (lookahead == 'a') ADVANCE(958);
      END_STATE();
    case 154:
      if (lookahead == 'a') ADVANCE(297);
      END_STATE();
    case 155:
      if (lookahead == 'a') ADVANCE(231);
      END_STATE();
    case 156:
      if (lookahead == 'a') ADVANCE(646);
      END_STATE();
    case 157:
      if (lookahead == 'a') ADVANCE(625);
      END_STATE();
    case 158:
      if (lookahead == 'a') ADVANCE(1057);
      END_STATE();
    case 159:
      if (lookahead == 'a') ADVANCE(299);
      END_STATE();
    case 160:
      if (lookahead == 'a') ADVANCE(896);
      END_STATE();
    case 161:
      if (lookahead == 'a') ADVANCE(302);
      END_STATE();
    case 162:
      if (lookahead == 'a') ADVANCE(303);
      END_STATE();
    case 163:
      if (lookahead == 'a') ADVANCE(304);
      END_STATE();
    case 164:
      if (lookahead == 'a') ADVANCE(186);
      if (lookahead == 'p') ADVANCE(129);
      END_STATE();
    case 165:
      if (lookahead == 'a') ADVANCE(827);
      END_STATE();
    case 166:
      if (lookahead == 'a') ADVANCE(1069);
      END_STATE();
    case 167:
      if (lookahead == 'a') ADVANCE(242);
      END_STATE();
    case 168:
      if (lookahead == 'a') ADVANCE(249);
      END_STATE();
    case 169:
      if (lookahead == 'a') ADVANCE(647);
      END_STATE();
    case 170:
      if (lookahead == 'a') ADVANCE(187);
      END_STATE();
    case 171:
      if (lookahead == 'a') ADVANCE(188);
      END_STATE();
    case 172:
      if (lookahead == 'a') ADVANCE(189);
      if (lookahead == 'p') ADVANCE(129);
      END_STATE();
    case 173:
      if (lookahead == 'a') ADVANCE(919);
      END_STATE();
    case 174:
      if (lookahead == 'a') ADVANCE(257);
      END_STATE();
    case 175:
      if (lookahead == 'a') ADVANCE(923);
      END_STATE();
    case 176:
      if (lookahead == 'a') ADVANCE(1078);
      END_STATE();
    case 177:
      if (lookahead == 'b') ADVANCE(736);
      if (lookahead == 'c') ADVANCE(201);
      if (lookahead == 'd') ADVANCE(265);
      if (lookahead == 'g') ADVANCE(493);
      if (lookahead == 'l') ADVANCE(602);
      if (lookahead == 'u') ADVANCE(1002);
      END_STATE();
    case 178:
      if (lookahead == 'b') ADVANCE(736);
      if (lookahead == 'c') ADVANCE(200);
      if (lookahead == 'l') ADVANCE(649);
      END_STATE();
    case 179:
      if (lookahead == 'b') ADVANCE(633);
      END_STATE();
    case 180:
      if (lookahead == 'b') ADVANCE(151);
      END_STATE();
    case 181:
      if (lookahead == 'b') ADVANCE(151);
      if (lookahead == 'o') ADVANCE(1114);
      END_STATE();
    case 182:
      if (lookahead == 'b') ADVANCE(146);
      END_STATE();
    case 183:
      if (lookahead == 'b') ADVANCE(126);
      END_STATE();
    case 184:
      if (lookahead == 'b') ADVANCE(326);
      END_STATE();
    case 185:
      if (lookahead == 'b') ADVANCE(332);
      END_STATE();
    case 186:
      if (lookahead == 'b') ADVANCE(634);
      END_STATE();
    case 187:
      if (lookahead == 'b') ADVANCE(638);
      END_STATE();
    case 188:
      if (lookahead == 'b') ADVANCE(639);
      END_STATE();
    case 189:
      if (lookahead == 'b') ADVANCE(640);
      END_STATE();
    case 190:
      if (lookahead == 'b') ADVANCE(155);
      END_STATE();
    case 191:
      if (lookahead == 'b') ADVANCE(152);
      END_STATE();
    case 192:
      if (lookahead == 'b') ADVANCE(174);
      END_STATE();
    case 193:
      if (lookahead == 'c') ADVANCE(575);
      if (lookahead == 'l') ADVANCE(119);
      END_STATE();
    case 194:
      if (lookahead == 'c') ADVANCE(1215);
      END_STATE();
    case 195:
      if (lookahead == 'c') ADVANCE(1385);
      END_STATE();
    case 196:
      if (lookahead == 'c') ADVANCE(500);
      END_STATE();
    case 197:
      if (lookahead == 'c') ADVANCE(592);
      if (lookahead == 'u') ADVANCE(902);
      END_STATE();
    case 198:
      if (lookahead == 'c') ADVANCE(769);
      if (lookahead == 'e') ADVANCE(684);
      if (lookahead == 'h') ADVANCE(729);
      if (lookahead == 'm') ADVANCE(1043);
      if (lookahead == 'o') ADVANCE(197);
      if (lookahead == 'p') ADVANCE(619);
      if (lookahead == 'r') ADVANCE(1103);
      if (lookahead == 's') ADVANCE(620);
      if (lookahead == 't') ADVANCE(122);
      END_STATE();
    case 199:
      if (lookahead == 'c') ADVANCE(769);
      if (lookahead == 'h') ADVANCE(729);
      if (lookahead == 'o') ADVANCE(245);
      END_STATE();
    case 200:
      if (lookahead == 'c') ADVANCE(362);
      END_STATE();
    case 201:
      if (lookahead == 'c') ADVANCE(362);
      if (lookahead == 'l') ADVANCE(1160);
      END_STATE();
    case 202:
      if (lookahead == 'c') ADVANCE(576);
      END_STATE();
    case 203:
      if (lookahead == 'c') ADVANCE(506);
      END_STATE();
    case 204:
      if (lookahead == 'c') ADVANCE(577);
      END_STATE();
    case 205:
      if (lookahead == 'c') ADVANCE(597);
      END_STATE();
    case 206:
      if (lookahead == 'c') ADVANCE(502);
      END_STATE();
    case 207:
      if (lookahead == 'c') ADVANCE(503);
      END_STATE();
    case 208:
      if (lookahead == 'c') ADVANCE(814);
      END_STATE();
    case 209:
      if (lookahead == 'c') ADVANCE(581);
      END_STATE();
    case 210:
      if (lookahead == 'c') ADVANCE(582);
      END_STATE();
    case 211:
      if (lookahead == 'c') ADVANCE(310);
      if (lookahead == 'w') ADVANCE(127);
      END_STATE();
    case 212:
      if (lookahead == 'c') ADVANCE(583);
      END_STATE();
    case 213:
      if (lookahead == 'c') ADVANCE(609);
      END_STATE();
    case 214:
      if (lookahead == 'c') ADVANCE(311);
      END_STATE();
    case 215:
      if (lookahead == 'c') ADVANCE(584);
      END_STATE();
    case 216:
      if (lookahead == 'c') ADVANCE(610);
      END_STATE();
    case 217:
      if (lookahead == 'c') ADVANCE(585);
      END_STATE();
    case 218:
      if (lookahead == 'c') ADVANCE(1005);
      END_STATE();
    case 219:
      if (lookahead == 'c') ADVANCE(586);
      END_STATE();
    case 220:
      if (lookahead == 'c') ADVANCE(593);
      END_STATE();
    case 221:
      if (lookahead == 'c') ADVANCE(589);
      END_STATE();
    case 222:
      if (lookahead == 'c') ADVANCE(1008);
      END_STATE();
    case 223:
      if (lookahead == 'c') ADVANCE(601);
      if (lookahead == 'g') ADVANCE(493);
      END_STATE();
    case 224:
      if (lookahead == 'c') ADVANCE(808);
      if (lookahead == 'r') ADVANCE(116);
      END_STATE();
    case 225:
      if (lookahead == 'c') ADVANCE(1014);
      END_STATE();
    case 226:
      if (lookahead == 'c') ADVANCE(167);
      END_STATE();
    case 227:
      if (lookahead == 'c') ADVANCE(317);
      END_STATE();
    case 228:
      if (lookahead == 'c') ADVANCE(319);
      END_STATE();
    case 229:
      if (lookahead == 'c') ADVANCE(1030);
      END_STATE();
    case 230:
      if (lookahead == 'c') ADVANCE(328);
      END_STATE();
    case 231:
      if (lookahead == 'c') ADVANCE(599);
      END_STATE();
    case 232:
      if (lookahead == 'c') ADVANCE(511);
      if (lookahead == 'r') ADVANCE(318);
      if (lookahead == 's') ADVANCE(665);
      END_STATE();
    case 233:
      if (lookahead == 'c') ADVANCE(511);
      if (lookahead == 's') ADVANCE(665);
      END_STATE();
    case 234:
      if (lookahead == 'c') ADVANCE(507);
      END_STATE();
    case 235:
      if (lookahead == 'c') ADVANCE(758);
      END_STATE();
    case 236:
      if (lookahead == 'c') ADVANCE(437);
      END_STATE();
    case 237:
      if (lookahead == 'c') ADVANCE(828);
      END_STATE();
    case 238:
      if (lookahead == 'c') ADVANCE(774);
      END_STATE();
    case 239:
      if (lookahead == 'c') ADVANCE(1083);
      END_STATE();
    case 240:
      if (lookahead == 'c') ADVANCE(884);
      END_STATE();
    case 241:
      if (lookahead == 'c') ADVANCE(595);
      END_STATE();
    case 242:
      if (lookahead == 'c') ADVANCE(512);
      END_STATE();
    case 243:
      if (lookahead == 'c') ADVANCE(475);
      if (lookahead == 'w') ADVANCE(127);
      END_STATE();
    case 244:
      if (lookahead == 'c') ADVANCE(648);
      END_STATE();
    case 245:
      if (lookahead == 'c') ADVANCE(596);
      END_STATE();
    case 246:
      if (lookahead == 'c') ADVANCE(383);
      END_STATE();
    case 247:
      if (lookahead == 'c') ADVANCE(248);
      END_STATE();
    case 248:
      if (lookahead == 'c') ADVANCE(400);
      END_STATE();
    case 249:
      if (lookahead == 'c') ADVANCE(395);
      END_STATE();
    case 250:
      if (lookahead == 'c') ADVANCE(513);
      if (lookahead == 'k') ADVANCE(414);
      if (lookahead == 'n') ADVANCE(760);
      if (lookahead == 'p') ADVANCE(895);
      if (lookahead == 'r') ADVANCE(472);
      if (lookahead == 's') ADVANCE(464);
      if (lookahead == 'u') ADVANCE(989);
      END_STATE();
    case 251:
      if (lookahead == 'c') ADVANCE(513);
      if (lookahead == 'r') ADVANCE(472);
      END_STATE();
    case 252:
      if (lookahead == 'c') ADVANCE(514);
      END_STATE();
    case 253:
      if (lookahead == 'c') ADVANCE(515);
      END_STATE();
    case 254:
      if (lookahead == 'c') ADVANCE(516);
      END_STATE();
    case 255:
      if (lookahead == 'c') ADVANCE(517);
      END_STATE();
    case 256:
      if (lookahead == 'c') ADVANCE(518);
      END_STATE();
    case 257:
      if (lookahead == 'c') ADVANCE(600);
      END_STATE();
    case 258:
      if (lookahead == 'c') ADVANCE(650);
      END_STATE();
    case 259:
      if (lookahead == 'c') ADVANCE(651);
      END_STATE();
    case 260:
      if (lookahead == 'c') ADVANCE(1081);
      END_STATE();
    case 261:
      if (lookahead == 'c') ADVANCE(847);
      if (lookahead == 'i') ADVANCE(657);
      END_STATE();
    case 262:
      if (lookahead == 'c') ADVANCE(478);
      END_STATE();
    case 263:
      if (lookahead == 'd') ADVANCE(1197);
      if (lookahead == 'f') ADVANCE(1443);
      if (lookahead == 'g') ADVANCE(710);
      if (lookahead == 'n') ADVANCE(283);
      END_STATE();
    case 264:
      if (lookahead == 'd') ADVANCE(1197);
      if (lookahead == 'g') ADVANCE(710);
      if (lookahead == 'n') ADVANCE(990);
      END_STATE();
    case 265:
      if (lookahead == 'd') ADVANCE(6);
      if (lookahead == 'm') ADVANCE(535);
      END_STATE();
    case 266:
      if (lookahead == 'd') ADVANCE(1163);
      END_STATE();
    case 267:
      if (lookahead == 'd') ADVANCE(1251);
      END_STATE();
    case 268:
      if (lookahead == 'd') ADVANCE(1281);
      END_STATE();
    case 269:
      if (lookahead == 'd') ADVANCE(1148);
      END_STATE();
    case 270:
      if (lookahead == 'd') ADVANCE(1199);
      END_STATE();
    case 271:
      if (lookahead == 'd') ADVANCE(1146);
      END_STATE();
    case 272:
      if (lookahead == 'd') ADVANCE(1219);
      END_STATE();
    case 273:
      if (lookahead == 'd') ADVANCE(1189);
      END_STATE();
    case 274:
      if (lookahead == 'd') ADVANCE(1187);
      END_STATE();
    case 275:
      if (lookahead == 'd') ADVANCE(1201);
      END_STATE();
    case 276:
      if (lookahead == 'd') ADVANCE(484);
      END_STATE();
    case 277:
      if (lookahead == 'd') ADVANCE(165);
      if (lookahead == 'i') ADVANCE(987);
      if (lookahead == 'o') ADVANCE(486);
      if (lookahead == 'u') ADVANCE(117);
      END_STATE();
    case 278:
      if (lookahead == 'd') ADVANCE(165);
      if (lookahead == 'o') ADVANCE(491);
      END_STATE();
    case 279:
      if (lookahead == 'd') ADVANCE(267);
      if (lookahead == 'l') ADVANCE(627);
      END_STATE();
    case 280:
      if (lookahead == 'd') ADVANCE(364);
      END_STATE();
    case 281:
      if (lookahead == 'd') ADVANCE(268);
      END_STATE();
    case 282:
      if (lookahead == 'd') ADVANCE(428);
      END_STATE();
    case 283:
      if (lookahead == 'd') ADVANCE(428);
      if (lookahead == 's') ADVANCE(825);
      END_STATE();
    case 284:
      if (lookahead == 'd') ADVANCE(309);
      if (lookahead == 'n') ADVANCE(537);
      END_STATE();
    case 285:
      if (lookahead == 'd') ADVANCE(655);
      if (lookahead == 'u') ADVANCE(1002);
      END_STATE();
    case 286:
      if (lookahead == 'd') ADVANCE(38);
      END_STATE();
    case 287:
      if (lookahead == 'd') ADVANCE(369);
      END_STATE();
    case 288:
      if (lookahead == 'd') ADVANCE(548);
      if (lookahead == 'q') ADVANCE(96);
      if (lookahead == 's') ADVANCE(745);
      if (lookahead == 't') ADVANCE(904);
      END_STATE();
    case 289:
      if (lookahead == 'd') ADVANCE(544);
      END_STATE();
    case 290:
      if (lookahead == 'd') ADVANCE(944);
      END_STATE();
    case 291:
      if (lookahead == 'd') ADVANCE(15);
      END_STATE();
    case 292:
      if (lookahead == 'd') ADVANCE(33);
      END_STATE();
    case 293:
      if (lookahead == 'd') ADVANCE(24);
      END_STATE();
    case 294:
      if (lookahead == 'd') ADVANCE(357);
      if (lookahead == 'r') ADVANCE(394);
      END_STATE();
    case 295:
      if (lookahead == 'd') ADVANCE(385);
      if (lookahead == 'l') ADVANCE(420);
      if (lookahead == 'n') ADVANCE(783);
      END_STATE();
    case 296:
      if (lookahead == 'd') ADVANCE(396);
      END_STATE();
    case 297:
      if (lookahead == 'd') ADVANCE(398);
      END_STATE();
    case 298:
      if (lookahead == 'd') ADVANCE(381);
      END_STATE();
    case 299:
      if (lookahead == 'd') ADVANCE(401);
      END_STATE();
    case 300:
      if (lookahead == 'd') ADVANCE(333);
      END_STATE();
    case 301:
      if (lookahead == 'd') ADVANCE(421);
      END_STATE();
    case 302:
      if (lookahead == 'd') ADVANCE(407);
      END_STATE();
    case 303:
      if (lookahead == 'd') ADVANCE(410);
      END_STATE();
    case 304:
      if (lookahead == 'd') ADVANCE(411);
      END_STATE();
    case 305:
      if (lookahead == 'd') ADVANCE(431);
      END_STATE();
    case 306:
      if (lookahead == 'd') ADVANCE(46);
      END_STATE();
    case 307:
      if (lookahead == 'e') ADVANCE(202);
      if (lookahead == 'r') ADVANCE(741);
      END_STATE();
    case 308:
      if (lookahead == 'e') ADVANCE(52);
      END_STATE();
    case 309:
      if (lookahead == 'e') ADVANCE(1168);
      END_STATE();
    case 310:
      if (lookahead == 'e') ADVANCE(37);
      END_STATE();
    case 311:
      if (lookahead == 'e') ADVANCE(1225);
      END_STATE();
    case 312:
      if (lookahead == 'e') ADVANCE(1375);
      END_STATE();
    case 313:
      if (lookahead == 'e') ADVANCE(606);
      END_STATE();
    case 314:
      if (lookahead == 'e') ADVANCE(1390);
      END_STATE();
    case 315:
      if (lookahead == 'e') ADVANCE(1183);
      END_STATE();
    case 316:
      if (lookahead == 'e') ADVANCE(1378);
      END_STATE();
    case 317:
      if (lookahead == 'e') ADVANCE(1195);
      END_STATE();
    case 318:
      if (lookahead == 'e') ADVANCE(851);
      END_STATE();
    case 319:
      if (lookahead == 'e') ADVANCE(1166);
      END_STATE();
    case 320:
      if (lookahead == 'e') ADVANCE(1211);
      END_STATE();
    case 321:
      if (lookahead == 'e') ADVANCE(1315);
      END_STATE();
    case 322:
      if (lookahead == 'e') ADVANCE(43);
      END_STATE();
    case 323:
      if (lookahead == 'e') ADVANCE(88);
      END_STATE();
    case 324:
      if (lookahead == 'e') ADVANCE(1447);
      END_STATE();
    case 325:
      if (lookahead == 'e') ADVANCE(1213);
      END_STATE();
    case 326:
      if (lookahead == 'e') ADVANCE(1277);
      END_STATE();
    case 327:
      if (lookahead == 'e') ADVANCE(1418);
      END_STATE();
    case 328:
      if (lookahead == 'e') ADVANCE(1399);
      END_STATE();
    case 329:
      if (lookahead == 'e') ADVANCE(1185);
      END_STATE();
    case 330:
      if (lookahead == 'e') ADVANCE(1227);
      END_STATE();
    case 331:
      if (lookahead == 'e') ADVANCE(1347);
      END_STATE();
    case 332:
      if (lookahead == 'e') ADVANCE(1269);
      END_STATE();
    case 333:
      if (lookahead == 'e') ADVANCE(1387);
      END_STATE();
    case 334:
      if (lookahead == 'e') ADVANCE(1342);
      END_STATE();
    case 335:
      if (lookahead == 'e') ADVANCE(1327);
      END_STATE();
    case 336:
      if (lookahead == 'e') ADVANCE(1408);
      END_STATE();
    case 337:
      if (lookahead == 'e') ADVANCE(1313);
      END_STATE();
    case 338:
      if (lookahead == 'e') ADVANCE(1333);
      END_STATE();
    case 339:
      if (lookahead == 'e') ADVANCE(1309);
      END_STATE();
    case 340:
      if (lookahead == 'e') ADVANCE(1303);
      END_STATE();
    case 341:
      if (lookahead == 'e') ADVANCE(1395);
      END_STATE();
    case 342:
      if (lookahead == 'e') ADVANCE(1415);
      END_STATE();
    case 343:
      if (lookahead == 'e') ADVANCE(1374);
      END_STATE();
    case 344:
      if (lookahead == 'e') ADVANCE(1363);
      END_STATE();
    case 345:
      if (lookahead == 'e') ADVANCE(1345);
      END_STATE();
    case 346:
      if (lookahead == 'e') ADVANCE(1247);
      END_STATE();
    case 347:
      if (lookahead == 'e') ADVANCE(1344);
      END_STATE();
    case 348:
      if (lookahead == 'e') ADVANCE(1335);
      END_STATE();
    case 349:
      if (lookahead == 'e') ADVANCE(1337);
      END_STATE();
    case 350:
      if (lookahead == 'e') ADVANCE(113);
      END_STATE();
    case 351:
      if (lookahead == 'e') ADVANCE(359);
      END_STATE();
    case 352:
      if (lookahead == 'e') ADVANCE(359);
      if (lookahead == 'g') ADVANCE(1001);
      END_STATE();
    case 353:
      if (lookahead == 'e') ADVANCE(660);
      END_STATE();
    case 354:
      if (lookahead == 'e') ADVANCE(607);
      END_STATE();
    case 355:
      if (lookahead == 'e') ADVANCE(494);
      END_STATE();
    case 356:
      if (lookahead == 'e') ADVANCE(611);
      END_STATE();
    case 357:
      if (lookahead == 'e') ADVANCE(612);
      END_STATE();
    case 358:
      if (lookahead == 'e') ADVANCE(966);
      END_STATE();
    case 359:
      if (lookahead == 'e') ADVANCE(859);
      if (lookahead == 'r') ADVANCE(953);
      END_STATE();
    case 360:
      if (lookahead == 'e') ADVANCE(218);
      END_STATE();
    case 361:
      if (lookahead == 'e') ADVANCE(954);
      END_STATE();
    case 362:
      if (lookahead == 'e') ADVANCE(823);
      END_STATE();
    case 363:
      if (lookahead == 'e') ADVANCE(739);
      END_STATE();
    case 364:
      if (lookahead == 'e') ADVANCE(29);
      END_STATE();
    case 365:
      if (lookahead == 'e') ADVANCE(675);
      END_STATE();
    case 366:
      if (lookahead == 'e') ADVANCE(1000);
      END_STATE();
    case 367:
      if (lookahead == 'e') ADVANCE(32);
      END_STATE();
    case 368:
      if (lookahead == 'e') ADVANCE(239);
      END_STATE();
    case 369:
      if (lookahead == 'e') ADVANCE(861);
      END_STATE();
    case 370:
      if (lookahead == 'e') ADVANCE(800);
      END_STATE();
    case 371:
      if (lookahead == 'e') ADVANCE(608);
      END_STATE();
    case 372:
      if (lookahead == 'e') ADVANCE(862);
      END_STATE();
    case 373:
      if (lookahead == 'e') ADVANCE(801);
      END_STATE();
    case 374:
      if (lookahead == 'e') ADVANCE(935);
      END_STATE();
    case 375:
      if (lookahead == 'e') ADVANCE(275);
      END_STATE();
    case 376:
      if (lookahead == 'e') ADVANCE(41);
      END_STATE();
    case 377:
      if (lookahead == 'e') ADVANCE(270);
      END_STATE();
    case 378:
      if (lookahead == 'e') ADVANCE(907);
      END_STATE();
    case 379:
      if (lookahead == 'e') ADVANCE(289);
      END_STATE();
    case 380:
      if (lookahead == 'e') ADVANCE(59);
      END_STATE();
    case 381:
      if (lookahead == 'e') ADVANCE(717);
      END_STATE();
    case 382:
      if (lookahead == 'e') ADVANCE(927);
      END_STATE();
    case 383:
      if (lookahead == 'e') ADVANCE(12);
      END_STATE();
    case 384:
      if (lookahead == 'e') ADVANCE(1035);
      END_STATE();
    case 385:
      if (lookahead == 'e') ADVANCE(960);
      END_STATE();
    case 386:
      if (lookahead == 'e') ADVANCE(864);
      END_STATE();
    case 387:
      if (lookahead == 'e') ADVANCE(833);
      END_STATE();
    case 388:
      if (lookahead == 'e') ADVANCE(26);
      END_STATE();
    case 389:
      if (lookahead == 'e') ADVANCE(1006);
      END_STATE();
    case 390:
      if (lookahead == 'e') ADVANCE(131);
      END_STATE();
    case 391:
      if (lookahead == 'e') ADVANCE(804);
      END_STATE();
    case 392:
      if (lookahead == 'e') ADVANCE(260);
      END_STATE();
    case 393:
      if (lookahead == 'e') ADVANCE(614);
      END_STATE();
    case 394:
      if (lookahead == 'e') ADVANCE(805);
      END_STATE();
    case 395:
      if (lookahead == 'e') ADVANCE(13);
      END_STATE();
    case 396:
      if (lookahead == 'e') ADVANCE(865);
      END_STATE();
    case 397:
      if (lookahead == 'e') ADVANCE(50);
      END_STATE();
    case 398:
      if (lookahead == 'e') ADVANCE(866);
      END_STATE();
    case 399:
      if (lookahead == 'e') ADVANCE(868);
      END_STATE();
    case 400:
      if (lookahead == 'e') ADVANCE(821);
      END_STATE();
    case 401:
      if (lookahead == 'e') ADVANCE(869);
      END_STATE();
    case 402:
      if (lookahead == 'e') ADVANCE(946);
      END_STATE();
    case 403:
      if (lookahead == 'e') ADVANCE(870);
      END_STATE();
    case 404:
      if (lookahead == 'e') ADVANCE(913);
      END_STATE();
    case 405:
      if (lookahead == 'e') ADVANCE(28);
      END_STATE();
    case 406:
      if (lookahead == 'e') ADVANCE(871);
      END_STATE();
    case 407:
      if (lookahead == 'e') ADVANCE(872);
      END_STATE();
    case 408:
      if (lookahead == 'e') ADVANCE(118);
      END_STATE();
    case 409:
      if (lookahead == 'e') ADVANCE(918);
      END_STATE();
    case 410:
      if (lookahead == 'e') ADVANCE(873);
      END_STATE();
    case 411:
      if (lookahead == 'e') ADVANCE(874);
      END_STATE();
    case 412:
      if (lookahead == 'e') ADVANCE(1020);
      END_STATE();
    case 413:
      if (lookahead == 'e') ADVANCE(1072);
      END_STATE();
    case 414:
      if (lookahead == 'e') ADVANCE(419);
      END_STATE();
    case 415:
      if (lookahead == 'e') ADVANCE(1032);
      END_STATE();
    case 416:
      if (lookahead == 'e') ADVANCE(1090);
      END_STATE();
    case 417:
      if (lookahead == 'e') ADVANCE(689);
      if (lookahead == 'l') ADVANCE(740);
      END_STATE();
    case 418:
      if (lookahead == 'e') ADVANCE(952);
      END_STATE();
    case 419:
      if (lookahead == 'e') ADVANCE(818);
      END_STATE();
    case 420:
      if (lookahead == 'e') ADVANCE(498);
      END_STATE();
    case 421:
      if (lookahead == 'e') ADVANCE(631);
      END_STATE();
    case 422:
      if (lookahead == 'e') ADVANCE(222);
      END_STATE();
    case 423:
      if (lookahead == 'e') ADVANCE(840);
      END_STATE();
    case 424:
      if (lookahead == 'e') ADVANCE(875);
      if (lookahead == 'o') ADVANCE(1086);
      if (lookahead == 't') ADVANCE(121);
      END_STATE();
    case 425:
      if (lookahead == 'e') ADVANCE(925);
      END_STATE();
    case 426:
      if (lookahead == 'e') ADVANCE(1059);
      END_STATE();
    case 427:
      if (lookahead == 'e') ADVANCE(691);
      END_STATE();
    case 428:
      if (lookahead == 'e') ADVANCE(838);
      END_STATE();
    case 429:
      if (lookahead == 'e') ADVANCE(694);
      if (lookahead == 't') ADVANCE(208);
      END_STATE();
    case 430:
      if (lookahead == 'e') ADVANCE(963);
      END_STATE();
    case 431:
      if (lookahead == 'e') ADVANCE(632);
      END_STATE();
    case 432:
      if (lookahead == 'e') ADVANCE(225);
      END_STATE();
    case 433:
      if (lookahead == 'e') ADVANCE(716);
      END_STATE();
    case 434:
      if (lookahead == 'e') ADVANCE(701);
      END_STATE();
    case 435:
      if (lookahead == 'e') ADVANCE(701);
      if (lookahead == 's') ADVANCE(1061);
      END_STATE();
    case 436:
      if (lookahead == 'e') ADVANCE(229);
      END_STATE();
    case 437:
      if (lookahead == 'e') ADVANCE(961);
      END_STATE();
    case 438:
      if (lookahead == 'e') ADVANCE(692);
      END_STATE();
    case 439:
      if (lookahead == 'e') ADVANCE(209);
      END_STATE();
    case 440:
      if (lookahead == 'e') ADVANCE(707);
      END_STATE();
    case 441:
      if (lookahead == 'e') ADVANCE(693);
      END_STATE();
    case 442:
      if (lookahead == 'e') ADVANCE(210);
      END_STATE();
    case 443:
      if (lookahead == 'e') ADVANCE(1110);
      END_STATE();
    case 444:
      if (lookahead == 'e') ADVANCE(711);
      END_STATE();
    case 445:
      if (lookahead == 'e') ADVANCE(212);
      END_STATE();
    case 446:
      if (lookahead == 'e') ADVANCE(967);
      END_STATE();
    case 447:
      if (lookahead == 'e') ADVANCE(695);
      END_STATE();
    case 448:
      if (lookahead == 'e') ADVANCE(215);
      END_STATE();
    case 449:
      if (lookahead == 'e') ADVANCE(969);
      END_STATE();
    case 450:
      if (lookahead == 'e') ADVANCE(423);
      END_STATE();
    case 451:
      if (lookahead == 'e') ADVANCE(217);
      END_STATE();
    case 452:
      if (lookahead == 'e') ADVANCE(219);
      END_STATE();
    case 453:
      if (lookahead == 'e') ADVANCE(971);
      END_STATE();
    case 454:
      if (lookahead == 'e') ADVANCE(220);
      END_STATE();
    case 455:
      if (lookahead == 'e') ADVANCE(221);
      END_STATE();
    case 456:
      if (lookahead == 'e') ADVANCE(974);
      END_STATE();
    case 457:
      if (lookahead == 'e') ADVANCE(976);
      END_STATE();
    case 458:
      if (lookahead == 'e') ADVANCE(150);
      END_STATE();
    case 459:
      if (lookahead == 'e') ADVANCE(852);
      END_STATE();
    case 460:
      if (lookahead == 'e') ADVANCE(645);
      END_STATE();
    case 461:
      if (lookahead == 'e') ADVANCE(911);
      END_STATE();
    case 462:
      if (lookahead == 'e') ADVANCE(1079);
      END_STATE();
    case 463:
      if (lookahead == 'e') ADVANCE(154);
      END_STATE();
    case 464:
      if (lookahead == 'e') ADVANCE(915);
      END_STATE();
    case 465:
      if (lookahead == 'e') ADVANCE(159);
      END_STATE();
    case 466:
      if (lookahead == 'e') ADVANCE(917);
      END_STATE();
    case 467:
      if (lookahead == 'e') ADVANCE(161);
      END_STATE();
    case 468:
      if (lookahead == 'e') ADVANCE(162);
      END_STATE();
    case 469:
      if (lookahead == 'e') ADVANCE(163);
      END_STATE();
    case 470:
      if (lookahead == 'e') ADVANCE(877);
      if (lookahead == 'g') ADVANCE(1001);
      END_STATE();
    case 471:
      if (lookahead == 'e') ADVANCE(1077);
      END_STATE();
    case 472:
      if (lookahead == 'e') ADVANCE(853);
      END_STATE();
    case 473:
      if (lookahead == 'e') ADVANCE(926);
      END_STATE();
    case 474:
      if (lookahead == 'e') ADVANCE(854);
      END_STATE();
    case 475:
      if (lookahead == 'e') ADVANCE(244);
      END_STATE();
    case 476:
      if (lookahead == 'e') ADVANCE(855);
      END_STATE();
    case 477:
      if (lookahead == 'e') ADVANCE(856);
      END_STATE();
    case 478:
      if (lookahead == 'e') ADVANCE(36);
      END_STATE();
    case 479:
      if (lookahead == 'f') ADVANCE(111);
      if (lookahead == 'l') ADVANCE(7);
      if (lookahead == 'n') ADVANCE(1121);
      if (lookahead == 's') ADVANCE(240);
      END_STATE();
    case 480:
      if (lookahead == 'f') ADVANCE(111);
      if (lookahead == 's') ADVANCE(240);
      END_STATE();
    case 481:
      if (lookahead == 'f') ADVANCE(556);
      END_STATE();
    case 482:
      if (lookahead == 'f') ADVANCE(753);
      END_STATE();
    case 483:
      if (lookahead == 'f') ADVANCE(753);
      if (lookahead == 'h') ADVANCE(390);
      if (lookahead == 's') ADVANCE(387);
      END_STATE();
    case 484:
      if (lookahead == 'f') ADVANCE(766);
      END_STATE();
    case 485:
      if (lookahead == 'f') ADVANCE(795);
      if (lookahead == 'h') ADVANCE(468);
      END_STATE();
    case 486:
      if (lookahead == 'g') ADVANCE(1178);
      END_STATE();
    case 487:
      if (lookahead == 'g') ADVANCE(1329);
      END_STATE();
    case 488:
      if (lookahead == 'g') ADVANCE(1205);
      END_STATE();
    case 489:
      if (lookahead == 'g') ADVANCE(47);
      END_STATE();
    case 490:
      if (lookahead == 'g') ADVANCE(1328);
      END_STATE();
    case 491:
      if (lookahead == 'g') ADVANCE(18);
      END_STATE();
    case 492:
      if (lookahead == 'g') ADVANCE(1180);
      END_STATE();
    case 493:
      if (lookahead == 'g') ADVANCE(885);
      END_STATE();
    case 494:
      if (lookahead == 'g') ADVANCE(176);
      END_STATE();
    case 495:
      if (lookahead == 'g') ADVANCE(386);
      END_STATE();
    case 496:
      if (lookahead == 'g') ADVANCE(39);
      END_STATE();
    case 497:
      if (lookahead == 'g') ADVANCE(542);
      END_STATE();
    case 498:
      if (lookahead == 'g') ADVANCE(438);
      END_STATE();
    case 499:
      if (lookahead == 'h') ADVANCE(1381);
      END_STATE();
    case 500:
      if (lookahead == 'h') ADVANCE(1412);
      END_STATE();
    case 501:
      if (lookahead == 'h') ADVANCE(1382);
      END_STATE();
    case 502:
      if (lookahead == 'h') ADVANCE(1203);
      END_STATE();
    case 503:
      if (lookahead == 'h') ADVANCE(1332);
      END_STATE();
    case 504:
      if (lookahead == 'h') ADVANCE(578);
      if (lookahead == 'l') ADVANCE(780);
      END_STATE();
    case 505:
      if (lookahead == 'h') ADVANCE(27);
      END_STATE();
    case 506:
      if (lookahead == 'h') ADVANCE(579);
      END_STATE();
    case 507:
      if (lookahead == 'h') ADVANCE(587);
      END_STATE();
    case 508:
      if (lookahead == 'h') ADVANCE(390);
      if (lookahead == 's') ADVANCE(387);
      END_STATE();
    case 509:
      if (lookahead == 'h') ADVANCE(460);
      END_STATE();
    case 510:
      if (lookahead == 'h') ADVANCE(1062);
      END_STATE();
    case 511:
      if (lookahead == 'h') ADVANCE(439);
      END_STATE();
    case 512:
      if (lookahead == 'h') ADVANCE(349);
      END_STATE();
    case 513:
      if (lookahead == 'h') ADVANCE(442);
      END_STATE();
    case 514:
      if (lookahead == 'h') ADVANCE(445);
      END_STATE();
    case 515:
      if (lookahead == 'h') ADVANCE(448);
      END_STATE();
    case 516:
      if (lookahead == 'h') ADVANCE(451);
      END_STATE();
    case 517:
      if (lookahead == 'h') ADVANCE(452);
      END_STATE();
    case 518:
      if (lookahead == 'h') ADVANCE(454);
      END_STATE();
    case 519:
      if (lookahead == 'h') ADVANCE(455);
      if (lookahead == 'l') ADVANCE(574);
      if (lookahead == 'o') ADVANCE(708);
      END_STATE();
    case 520:
      if (lookahead == 'h') ADVANCE(465);
      if (lookahead == 'l') ADVANCE(744);
      if (lookahead == 'm') ADVANCE(99);
      if (lookahead == 'n') ADVANCE(561);
      if (lookahead == 't') ADVANCE(754);
      END_STATE();
    case 521:
      if (lookahead == 'h') ADVANCE(467);
      if (lookahead == 'v') ADVANCE(134);
      END_STATE();
    case 522:
      if (lookahead == 'h') ADVANCE(57);
      END_STATE();
    case 523:
      if (lookahead == 'h') ADVANCE(469);
      END_STATE();
    case 524:
      if (lookahead == 'i') ADVANCE(280);
      if (lookahead == 't') ADVANCE(1074);
      END_STATE();
    case 525:
      if (lookahead == 'i') ADVANCE(429);
      END_STATE();
    case 526:
      if (lookahead == 'i') ADVANCE(1379);
      END_STATE();
    case 527:
      if (lookahead == 'i') ADVANCE(922);
      END_STATE();
    case 528:
      if (lookahead == 'i') ADVANCE(1223);
      END_STATE();
    case 529:
      if (lookahead == 'i') ADVANCE(1132);
      END_STATE();
    case 530:
      if (lookahead == 'i') ADVANCE(850);
      END_STATE();
    case 531:
      if (lookahead == 'i') ADVANCE(850);
      if (lookahead == 'l') ADVANCE(361);
      END_STATE();
    case 532:
      if (lookahead == 'i') ADVANCE(987);
      if (lookahead == 'o') ADVANCE(492);
      if (lookahead == 'u') ADVANCE(117);
      END_STATE();
    case 533:
      if (lookahead == 'i') ADVANCE(603);
      END_STATE();
    case 534:
      if (lookahead == 'i') ADVANCE(666);
      END_STATE();
    case 535:
      if (lookahead == 'i') ADVANCE(673);
      END_STATE();
    case 536:
      if (lookahead == 'i') ADVANCE(686);
      END_STATE();
    case 537:
      if (lookahead == 'i') ADVANCE(1066);
      END_STATE();
    case 538:
      if (lookahead == 'i') ADVANCE(497);
      END_STATE();
    case 539:
      if (lookahead == 'i') ADVANCE(685);
      END_STATE();
    case 540:
      if (lookahead == 'i') ADVANCE(845);
      END_STATE();
    case 541:
      if (lookahead == 'i') ADVANCE(1007);
      END_STATE();
    case 542:
      if (lookahead == 'i') ADVANCE(706);
      END_STATE();
    case 543:
      if (lookahead == 'i') ADVANCE(315);
      END_STATE();
    case 544:
      if (lookahead == 'i') ADVANCE(950);
      END_STATE();
    case 545:
      if (lookahead == 'i') ADVANCE(1016);
      END_STATE();
    case 546:
      if (lookahead == 'i') ADVANCE(1018);
      END_STATE();
    case 547:
      if (lookahead == 'i') ADVANCE(374);
      END_STATE();
    case 548:
      if (lookahead == 'i') ADVANCE(921);
      END_STATE();
    case 549:
      if (lookahead == 'i') ADVANCE(1019);
      END_STATE();
    case 550:
      if (lookahead == 'i') ADVANCE(335);
      END_STATE();
    case 551:
      if (lookahead == 'i') ADVANCE(402);
      END_STATE();
    case 552:
      if (lookahead == 'i') ADVANCE(657);
      END_STATE();
    case 553:
      if (lookahead == 'i') ADVANCE(962);
      END_STATE();
    case 554:
      if (lookahead == 'i') ADVANCE(291);
      END_STATE();
    case 555:
      if (lookahead == 'i') ADVANCE(246);
      END_STATE();
    case 556:
      if (lookahead == 'i') ADVANCE(636);
      END_STATE();
    case 557:
      if (lookahead == 'i') ADVANCE(750);
      END_STATE();
    case 558:
      if (lookahead == 'i') ADVANCE(293);
      END_STATE();
    case 559:
      if (lookahead == 'i') ADVANCE(1056);
      END_STATE();
    case 560:
      if (lookahead == 'i') ADVANCE(965);
      END_STATE();
    case 561:
      if (lookahead == 'i') ADVANCE(230);
      END_STATE();
    case 562:
      if (lookahead == 'i') ADVANCE(777);
      END_STATE();
    case 563:
      if (lookahead == 'i') ADVANCE(1112);
      END_STATE();
    case 564:
      if (lookahead == 'i') ADVANCE(718);
      END_STATE();
    case 565:
      if (lookahead == 'i') ADVANCE(757);
      END_STATE();
    case 566:
      if (lookahead == 'i') ADVANCE(1113);
      END_STATE();
    case 567:
      if (lookahead == 'i') ADVANCE(970);
      END_STATE();
    case 568:
      if (lookahead == 'i') ADVANCE(779);
      END_STATE();
    case 569:
      if (lookahead == 'i') ADVANCE(759);
      END_STATE();
    case 570:
      if (lookahead == 'i') ADVANCE(972);
      END_STATE();
    case 571:
      if (lookahead == 'i') ADVANCE(761);
      END_STATE();
    case 572:
      if (lookahead == 'i') ADVANCE(763);
      END_STATE();
    case 573:
      if (lookahead == 'i') ADVANCE(765);
      END_STATE();
    case 574:
      if (lookahead == 'i') ADVANCE(1040);
      END_STATE();
    case 575:
      if (lookahead == 'k') ADVANCE(417);
      END_STATE();
    case 576:
      if (lookahead == 'k') ADVANCE(1371);
      END_STATE();
    case 577:
      if (lookahead == 'k') ADVANCE(1312);
      END_STATE();
    case 578:
      if (lookahead == 'k') ADVANCE(1330);
      END_STATE();
    case 579:
      if (lookahead == 'k') ADVANCE(1359);
      END_STATE();
    case 580:
      if (lookahead == 'k') ADVANCE(1401);
      END_STATE();
    case 581:
      if (lookahead == 'k') ADVANCE(1366);
      END_STATE();
    case 582:
      if (lookahead == 'k') ADVANCE(1305);
      END_STATE();
    case 583:
      if (lookahead == 'k') ADVANCE(1350);
      END_STATE();
    case 584:
      if (lookahead == 'k') ADVANCE(1354);
      END_STATE();
    case 585:
      if (lookahead == 'k') ADVANCE(1355);
      END_STATE();
    case 586:
      if (lookahead == 'k') ADVANCE(1358);
      END_STATE();
    case 587:
      if (lookahead == 'k') ADVANCE(1365);
      END_STATE();
    case 588:
      if (lookahead == 'k') ADVANCE(543);
      END_STATE();
    case 589:
      if (lookahead == 'k') ADVANCE(226);
      END_STATE();
    case 590:
      if (lookahead == 'k') ADVANCE(100);
      END_STATE();
    case 591:
      if (lookahead == 'k') ADVANCE(101);
      END_STATE();
    case 592:
      if (lookahead == 'k') ADVANCE(389);
      END_STATE();
    case 593:
      if (lookahead == 'k') ADVANCE(947);
      END_STATE();
    case 594:
      if (lookahead == 'k') ADVANCE(450);
      END_STATE();
    case 595:
      if (lookahead == 'k') ADVANCE(471);
      END_STATE();
    case 596:
      if (lookahead == 'k') ADVANCE(415);
      END_STATE();
    case 597:
      if (lookahead == 'k') ADVANCE(1091);
      END_STATE();
    case 598:
      if (lookahead == 'k') ADVANCE(550);
      END_STATE();
    case 599:
      if (lookahead == 'k') ADVANCE(441);
      END_STATE();
    case 600:
      if (lookahead == 'k') ADVANCE(447);
      END_STATE();
    case 601:
      if (lookahead == 'l') ADVANCE(1160);
      END_STATE();
    case 602:
      if (lookahead == 'l') ADVANCE(181);
      END_STATE();
    case 603:
      if (lookahead == 'l') ADVANCE(1321);
      END_STATE();
    case 604:
      if (lookahead == 'l') ADVANCE(1102);
      END_STATE();
    case 605:
      if (lookahead == 'l') ADVANCE(1142);
      END_STATE();
    case 606:
      if (lookahead == 'l') ADVANCE(1255);
      if (lookahead == 'n') ADVANCE(1122);
      END_STATE();
    case 607:
      if (lookahead == 'l') ADVANCE(1283);
      if (lookahead == 'n') ADVANCE(1123);
      END_STATE();
    case 608:
      if (lookahead == 'l') ADVANCE(1377);
      END_STATE();
    case 609:
      if (lookahead == 'l') ADVANCE(1402);
      END_STATE();
    case 610:
      if (lookahead == 'l') ADVANCE(1403);
      END_STATE();
    case 611:
      if (lookahead == 'l') ADVANCE(1261);
      if (lookahead == 'n') ADVANCE(1124);
      END_STATE();
    case 612:
      if (lookahead == 'l') ADVANCE(1287);
      if (lookahead == 'n') ADVANCE(1125);
      END_STATE();
    case 613:
      if (lookahead == 'l') ADVANCE(1341);
      END_STATE();
    case 614:
      if (lookahead == 'l') ADVANCE(1398);
      END_STATE();
    case 615:
      if (lookahead == 'l') ADVANCE(1340);
      END_STATE();
    case 616:
      if (lookahead == 'l') ADVANCE(87);
      END_STATE();
    case 617:
      if (lookahead == 'l') ADVANCE(770);
      if (lookahead == 'r') ADVANCE(109);
      END_STATE();
    case 618:
      if (lookahead == 'l') ADVANCE(654);
      END_STATE();
    case 619:
      if (lookahead == 'l') ADVANCE(555);
      END_STATE();
    case 620:
      if (lookahead == 'l') ADVANCE(22);
      END_STATE();
    case 621:
      if (lookahead == 'l') ADVANCE(742);
      END_STATE();
    case 622:
      if (lookahead == 'l') ADVANCE(534);
      END_STATE();
    case 623:
      if (lookahead == 'l') ADVANCE(168);
      END_STATE();
    case 624:
      if (lookahead == 'l') ADVANCE(762);
      END_STATE();
    case 625:
      if (lookahead == 'l') ADVANCE(563);
      END_STATE();
    case 626:
      if (lookahead == 'l') ADVANCE(613);
      END_STATE();
    case 627:
      if (lookahead == 'l') ADVANCE(735);
      END_STATE();
    case 628:
      if (lookahead == 'l') ADVANCE(1010);
      END_STATE();
    case 629:
      if (lookahead == 'l') ADVANCE(737);
      END_STATE();
    case 630:
      if (lookahead == 'l') ADVANCE(778);
      END_STATE();
    case 631:
      if (lookahead == 'l') ADVANCE(120);
      END_STATE();
    case 632:
      if (lookahead == 'l') ADVANCE(123);
      END_STATE();
    case 633:
      if (lookahead == 'l') ADVANCE(316);
      END_STATE();
    case 634:
      if (lookahead == 'l') ADVANCE(322);
      END_STATE();
    case 635:
      if (lookahead == 'l') ADVANCE(1054);
      END_STATE();
    case 636:
      if (lookahead == 'l') ADVANCE(329);
      END_STATE();
    case 637:
      if (lookahead == 'l') ADVANCE(443);
      END_STATE();
    case 638:
      if (lookahead == 'l') ADVANCE(337);
      END_STATE();
    case 639:
      if (lookahead == 'l') ADVANCE(375);
      END_STATE();
    case 640:
      if (lookahead == 'l') ADVANCE(377);
      END_STATE();
    case 641:
      if (lookahead == 'l') ADVANCE(1058);
      END_STATE();
    case 642:
      if (lookahead == 'l') ADVANCE(536);
      END_STATE();
    case 643:
      if (lookahead == 'l') ADVANCE(1094);
      END_STATE();
    case 644:
      if (lookahead == 'l') ADVANCE(629);
      END_STATE();
    case 645:
      if (lookahead == 'l') ADVANCE(630);
      END_STATE();
    case 646:
      if (lookahead == 'l') ADVANCE(558);
      END_STATE();
    case 647:
      if (lookahead == 'l') ADVANCE(566);
      END_STATE();
    case 648:
      if (lookahead == 'l') ADVANCE(782);
      END_STATE();
    case 649:
      if (lookahead == 'l') ADVANCE(180);
      END_STATE();
    case 650:
      if (lookahead == 'l') ADVANCE(784);
      END_STATE();
    case 651:
      if (lookahead == 'l') ADVANCE(785);
      END_STATE();
    case 652:
      if (lookahead == 'l') ADVANCE(53);
      END_STATE();
    case 653:
      if (lookahead == 'l') ADVANCE(55);
      END_STATE();
    case 654:
      if (lookahead == 'm') ADVANCE(1380);
      END_STATE();
    case 655:
      if (lookahead == 'm') ADVANCE(535);
      END_STATE();
    case 656:
      if (lookahead == 'm') ADVANCE(358);
      END_STATE();
    case 657:
      if (lookahead == 'm') ADVANCE(363);
      END_STATE();
    case 658:
      if (lookahead == 'm') ADVANCE(948);
      END_STATE();
    case 659:
      if (lookahead == 'm') ADVANCE(137);
      END_STATE();
    case 660:
      if (lookahead == 'm') ADVANCE(747);
      END_STATE();
    case 661:
      if (lookahead == 'm') ADVANCE(834);
      if (lookahead == 'n') ADVANCE(725);
      if (lookahead == 'o') ADVANCE(588);
      END_STATE();
    case 662:
      if (lookahead == 'm') ADVANCE(834);
      if (lookahead == 'n') ADVANCE(713);
      if (lookahead == 'o') ADVANCE(588);
      END_STATE();
    case 663:
      if (lookahead == 'm') ADVANCE(1043);
      if (lookahead == 'o') ADVANCE(241);
      if (lookahead == 'p') ADVANCE(619);
      if (lookahead == 'r') ADVANCE(1103);
      if (lookahead == 's') ADVANCE(620);
      END_STATE();
    case 664:
      if (lookahead == 'm') ADVANCE(130);
      END_STATE();
    case 665:
      if (lookahead == 'm') ADVANCE(135);
      END_STATE();
    case 666:
      if (lookahead == 'm') ADVANCE(546);
      END_STATE();
    case 667:
      if (lookahead == 'm') ADVANCE(141);
      END_STATE();
    case 668:
      if (lookahead == 'm') ADVANCE(143);
      END_STATE();
    case 669:
      if (lookahead == 'n') ADVANCE(106);
      END_STATE();
    case 670:
      if (lookahead == 'n') ADVANCE(106);
      if (lookahead == 'r') ADVANCE(900);
      if (lookahead == 'x') ADVANCE(811);
      END_STATE();
    case 671:
      if (lookahead == 'n') ADVANCE(1413);
      if (lookahead == 'p') ADVANCE(1038);
      if (lookahead == 'r') ADVANCE(1439);
      END_STATE();
    case 672:
      if (lookahead == 'n') ADVANCE(531);
      if (lookahead == 'r') ADVANCE(526);
      if (lookahead == 's') ADVANCE(308);
      END_STATE();
    case 673:
      if (lookahead == 'n') ADVANCE(1383);
      END_STATE();
    case 674:
      if (lookahead == 'n') ADVANCE(1176);
      END_STATE();
    case 675:
      if (lookahead == 'n') ADVANCE(1150);
      END_STATE();
    case 676:
      if (lookahead == 'n') ADVANCE(1295);
      END_STATE();
    case 677:
      if (lookahead == 'n') ADVANCE(1170);
      END_STATE();
    case 678:
      if (lookahead == 'n') ADVANCE(86);
      END_STATE();
    case 679:
      if (lookahead == 'n') ADVANCE(1191);
      END_STATE();
    case 680:
      if (lookahead == 'n') ADVANCE(1207);
      END_STATE();
    case 681:
      if (lookahead == 'n') ADVANCE(1384);
      END_STATE();
    case 682:
      if (lookahead == 'n') ADVANCE(1409);
      END_STATE();
    case 683:
      if (lookahead == 'n') ADVANCE(266);
      END_STATE();
    case 684:
      if (lookahead == 'n') ADVANCE(286);
      if (lookahead == 'r') ADVANCE(1104);
      if (lookahead == 's') ADVANCE(991);
      if (lookahead == 't') ADVANCE(8);
      END_STATE();
    case 685:
      if (lookahead == 'n') ADVANCE(1105);
      END_STATE();
    case 686:
      if (lookahead == 'n') ADVANCE(495);
      END_STATE();
    case 687:
      if (lookahead == 'n') ADVANCE(705);
      END_STATE();
    case 688:
      if (lookahead == 'n') ADVANCE(1041);
      END_STATE();
    case 689:
      if (lookahead == 'n') ADVANCE(269);
      END_STATE();
    case 690:
      if (lookahead == 'n') ADVANCE(957);
      END_STATE();
    case 691:
      if (lookahead == 'n') ADVANCE(271);
      END_STATE();
    case 692:
      if (lookahead == 'n') ADVANCE(290);
      END_STATE();
    case 693:
      if (lookahead == 'n') ADVANCE(273);
      END_STATE();
    case 694:
      if (lookahead == 'n') ADVANCE(1004);
      END_STATE();
    case 695:
      if (lookahead == 'n') ADVANCE(274);
      END_STATE();
    case 696:
      if (lookahead == 'n') ADVANCE(677);
      END_STATE();
    case 697:
      if (lookahead == 'n') ADVANCE(258);
      END_STATE();
    case 698:
      if (lookahead == 'n') ADVANCE(760);
      if (lookahead == 'p') ADVANCE(895);
      if (lookahead == 's') ADVANCE(464);
      if (lookahead == 'u') ADVANCE(989);
      END_STATE();
    case 699:
      if (lookahead == 'n') ADVANCE(938);
      END_STATE();
    case 700:
      if (lookahead == 'n') ADVANCE(530);
      if (lookahead == 's') ADVANCE(308);
      END_STATE();
    case 701:
      if (lookahead == 'n') ADVANCE(1009);
      END_STATE();
    case 702:
      if (lookahead == 'n') ADVANCE(727);
      END_STATE();
    case 703:
      if (lookahead == 'n') ADVANCE(942);
      END_STATE();
    case 704:
      if (lookahead == 'n') ADVANCE(16);
      END_STATE();
    case 705:
      if (lookahead == 'n') ADVANCE(371);
      END_STATE();
    case 706:
      if (lookahead == 'n') ADVANCE(148);
      END_STATE();
    case 707:
      if (lookahead == 'n') ADVANCE(1022);
      END_STATE();
    case 708:
      if (lookahead == 'n') ADVANCE(1075);
      END_STATE();
    case 709:
      if (lookahead == 'n') ADVANCE(412);
      if (lookahead == 'u') ADVANCE(886);
      END_STATE();
    case 710:
      if (lookahead == 'n') ADVANCE(790);
      END_STATE();
    case 711:
      if (lookahead == 'n') ADVANCE(292);
      END_STATE();
    case 712:
      if (lookahead == 'n') ADVANCE(1055);
      END_STATE();
    case 713:
      if (lookahead == 'n') ADVANCE(392);
      if (lookahead == 't') ADVANCE(434);
      END_STATE();
    case 714:
      if (lookahead == 'n') ADVANCE(228);
      END_STATE();
    case 715:
      if (lookahead == 'n') ADVANCE(977);
      END_STATE();
    case 716:
      if (lookahead == 'n') ADVANCE(298);
      END_STATE();
    case 717:
      if (lookahead == 'n') ADVANCE(1073);
      END_STATE();
    case 718:
      if (lookahead == 'n') ADVANCE(306);
      END_STATE();
    case 719:
      if (lookahead == 'n') ADVANCE(981);
      END_STATE();
    case 720:
      if (lookahead == 'n') ADVANCE(982);
      END_STATE();
    case 721:
      if (lookahead == 'n') ADVANCE(983);
      END_STATE();
    case 722:
      if (lookahead == 'n') ADVANCE(984);
      END_STATE();
    case 723:
      if (lookahead == 'n') ADVANCE(282);
      END_STATE();
    case 724:
      if (lookahead == 'n') ADVANCE(986);
      END_STATE();
    case 725:
      if (lookahead == 'n') ADVANCE(422);
      if (lookahead == 't') ADVANCE(435);
      END_STATE();
    case 726:
      if (lookahead == 'n') ADVANCE(788);
      END_STATE();
    case 727:
      if (lookahead == 'n') ADVANCE(436);
      END_STATE();
    case 728:
      if (lookahead == 'n') ADVANCE(171);
      if (lookahead == 'r') ADVANCE(900);
      END_STATE();
    case 729:
      if (lookahead == 'o') ADVANCE(1117);
      END_STATE();
    case 730:
      if (lookahead == 'o') ADVANCE(1119);
      END_STATE();
    case 731:
      if (lookahead == 'o') ADVANCE(1361);
      END_STATE();
    case 732:
      if (lookahead == 'o') ADVANCE(1357);
      END_STATE();
    case 733:
      if (lookahead == 'o') ADVANCE(642);
      END_STATE();
    case 734:
      if (lookahead == 'o') ADVANCE(688);
      END_STATE();
    case 735:
      if (lookahead == 'o') ADVANCE(1115);
      END_STATE();
    case 736:
      if (lookahead == 'o') ADVANCE(882);
      END_STATE();
    case 737:
      if (lookahead == 'o') ADVANCE(1116);
      END_STATE();
    case 738:
      if (lookahead == 'o') ADVANCE(487);
      END_STATE();
    case 739:
      if (lookahead == 'o') ADVANCE(1092);
      END_STATE();
    case 740:
      if (lookahead == 'o') ADVANCE(488);
      END_STATE();
    case 741:
      if (lookahead == 'o') ADVANCE(749);
      END_STATE();
    case 742:
      if (lookahead == 'o') ADVANCE(489);
      END_STATE();
    case 743:
      if (lookahead == 'o') ADVANCE(490);
      END_STATE();
    case 744:
      if (lookahead == 'o') ADVANCE(496);
      END_STATE();
    case 745:
      if (lookahead == 'o') ADVANCE(604);
      END_STATE();
    case 746:
      if (lookahead == 'o') ADVANCE(604);
      if (lookahead == 'p') ADVANCE(775);
      END_STATE();
    case 747:
      if (lookahead == 'o') ADVANCE(674);
      END_STATE();
    case 748:
      if (lookahead == 'o') ADVANCE(860);
      END_STATE();
    case 749:
      if (lookahead == 'o') ADVANCE(1003);
      END_STATE();
    case 750:
      if (lookahead == 'o') ADVANCE(676);
      END_STATE();
    case 751:
      if (lookahead == 'o') ADVANCE(697);
      END_STATE();
    case 752:
      if (lookahead == 'o') ADVANCE(194);
      END_STATE();
    case 753:
      if (lookahead == 'o') ADVANCE(903);
      END_STATE();
    case 754:
      if (lookahead == 'o') ADVANCE(936);
      END_STATE();
    case 755:
      if (lookahead == 'o') ADVANCE(863);
      END_STATE();
    case 756:
      if (lookahead == 'o') ADVANCE(704);
      END_STATE();
    case 757:
      if (lookahead == 'o') ADVANCE(678);
      END_STATE();
    case 758:
      if (lookahead == 'o') ADVANCE(786);
      END_STATE();
    case 759:
      if (lookahead == 'o') ADVANCE(679);
      END_STATE();
    case 760:
      if (lookahead == 'o') ADVANCE(42);
      END_STATE();
    case 761:
      if (lookahead == 'o') ADVANCE(680);
      END_STATE();
    case 762:
      if (lookahead == 'o') ADVANCE(124);
      END_STATE();
    case 763:
      if (lookahead == 'o') ADVANCE(681);
      END_STATE();
    case 764:
      if (lookahead == 'o') ADVANCE(616);
      END_STATE();
    case 765:
      if (lookahead == 'o') ADVANCE(682);
      END_STATE();
    case 766:
      if (lookahead == 'o') ADVANCE(867);
      END_STATE();
    case 767:
      if (lookahead == 'o') ADVANCE(764);
      END_STATE();
    case 768:
      if (lookahead == 'o') ADVANCE(892);
      END_STATE();
    case 769:
      if (lookahead == 'o') ADVANCE(819);
      END_STATE();
    case 770:
      if (lookahead == 'o') ADVANCE(183);
      END_STATE();
    case 771:
      if (lookahead == 'o') ADVANCE(1120);
      END_STATE();
    case 772:
      if (lookahead == 'o') ADVANCE(712);
      END_STATE();
    case 773:
      if (lookahead == 'o') ADVANCE(901);
      END_STATE();
    case 774:
      if (lookahead == 'o') ADVANCE(696);
      END_STATE();
    case 775:
      if (lookahead == 'o') ADVANCE(715);
      END_STATE();
    case 776:
      if (lookahead == 'o') ADVANCE(702);
      END_STATE();
    case 777:
      if (lookahead == 'o') ADVANCE(699);
      END_STATE();
    case 778:
      if (lookahead == 'o') ADVANCE(31);
      END_STATE();
    case 779:
      if (lookahead == 'o') ADVANCE(703);
      END_STATE();
    case 780:
      if (lookahead == 'o') ADVANCE(978);
      END_STATE();
    case 781:
      if (lookahead == 'o') ADVANCE(236);
      END_STATE();
    case 782:
      if (lookahead == 'o') ADVANCE(979);
      END_STATE();
    case 783:
      if (lookahead == 'o') ADVANCE(300);
      END_STATE();
    case 784:
      if (lookahead == 'o') ADVANCE(980);
      END_STATE();
    case 785:
      if (lookahead == 'o') ADVANCE(985);
      END_STATE();
    case 786:
      if (lookahead == 'o') ADVANCE(598);
      END_STATE();
    case 787:
      if (lookahead == 'o') ADVANCE(924);
      if (lookahead == 'r') ADVANCE(772);
      END_STATE();
    case 788:
      if (lookahead == 'o') ADVANCE(908);
      END_STATE();
    case 789:
      if (lookahead == 'o') ADVANCE(719);
      END_STATE();
    case 790:
      if (lookahead == 'o') ADVANCE(912);
      END_STATE();
    case 791:
      if (lookahead == 'o') ADVANCE(720);
      END_STATE();
    case 792:
      if (lookahead == 'o') ADVANCE(721);
      END_STATE();
    case 793:
      if (lookahead == 'o') ADVANCE(722);
      END_STATE();
    case 794:
      if (lookahead == 'o') ADVANCE(724);
      END_STATE();
    case 795:
      if (lookahead == 'o') ADVANCE(920);
      END_STATE();
    case 796:
      if (lookahead == 'p') ADVANCE(110);
      END_STATE();
    case 797:
      if (lookahead == 'p') ADVANCE(9);
      END_STATE();
    case 798:
      if (lookahead == 'p') ADVANCE(10);
      END_STATE();
    case 799:
      if (lookahead == 'p') ADVANCE(1174);
      END_STATE();
    case 800:
      if (lookahead == 'p') ADVANCE(1275);
      END_STATE();
    case 801:
      if (lookahead == 'p') ADVANCE(1293);
      END_STATE();
    case 802:
      if (lookahead == 'p') ADVANCE(1217);
      END_STATE();
    case 803:
      if (lookahead == 'p') ADVANCE(1405);
      END_STATE();
    case 804:
      if (lookahead == 'p') ADVANCE(1267);
      END_STATE();
    case 805:
      if (lookahead == 'p') ADVANCE(1291);
      END_STATE();
    case 806:
      if (lookahead == 'p') ADVANCE(1404);
      if (lookahead == 'r') ADVANCE(580);
      END_STATE();
    case 807:
      if (lookahead == 'p') ADVANCE(1353);
      END_STATE();
    case 808:
      if (lookahead == 'p') ADVANCE(19);
      END_STATE();
    case 809:
      if (lookahead == 'p') ADVANCE(20);
      END_STATE();
    case 810:
      if (lookahead == 'p') ADVANCE(1038);
      END_STATE();
    case 811:
      if (lookahead == 'p') ADVANCE(360);
      END_STATE();
    case 812:
      if (lookahead == 'p') ADVANCE(879);
      END_STATE();
    case 813:
      if (lookahead == 'p') ADVANCE(23);
      END_STATE();
    case 814:
      if (lookahead == 'p') ADVANCE(590);
      END_STATE();
    case 815:
      if (lookahead == 'p') ADVANCE(203);
      END_STATE();
    case 816:
      if (lookahead == 'p') ADVANCE(941);
      END_STATE();
    case 817:
      if (lookahead == 'p') ADVANCE(160);
      END_STATE();
    case 818:
      if (lookahead == 'p') ADVANCE(48);
      END_STATE();
    case 819:
      if (lookahead == 'p') ADVANCE(314);
      END_STATE();
    case 820:
      if (lookahead == 'p') ADVANCE(17);
      END_STATE();
    case 821:
      if (lookahead == 'p') ADVANCE(1028);
      END_STATE();
    case 822:
      if (lookahead == 'p') ADVANCE(330);
      END_STATE();
    case 823:
      if (lookahead == 'p') ADVANCE(1045);
      END_STATE();
    case 824:
      if (lookahead == 'p') ADVANCE(541);
      END_STATE();
    case 825:
      if (lookahead == 'p') ADVANCE(368);
      END_STATE();
    case 826:
      if (lookahead == 'p') ADVANCE(889);
      END_STATE();
    case 827:
      if (lookahead == 'p') ADVANCE(25);
      END_STATE();
    case 828:
      if (lookahead == 'p') ADVANCE(591);
      END_STATE();
    case 829:
      if (lookahead == 'p') ADVANCE(425);
      END_STATE();
    case 830:
      if (lookahead == 'p') ADVANCE(545);
      END_STATE();
    case 831:
      if (lookahead == 'p') ADVANCE(767);
      END_STATE();
    case 832:
      if (lookahead == 'p') ADVANCE(890);
      END_STATE();
    case 833:
      if (lookahead == 'p') ADVANCE(136);
      END_STATE();
    case 834:
      if (lookahead == 'p') ADVANCE(891);
      END_STATE();
    case 835:
      if (lookahead == 'p') ADVANCE(905);
      END_STATE();
    case 836:
      if (lookahead == 'p') ADVANCE(549);
      END_STATE();
    case 837:
      if (lookahead == 'p') ADVANCE(44);
      END_STATE();
    case 838:
      if (lookahead == 'p') ADVANCE(433);
      END_STATE();
    case 839:
      if (lookahead == 'p') ADVANCE(789);
      END_STATE();
    case 840:
      if (lookahead == 'p') ADVANCE(169);
      END_STATE();
    case 841:
      if (lookahead == 'p') ADVANCE(791);
      END_STATE();
    case 842:
      if (lookahead == 'p') ADVANCE(792);
      END_STATE();
    case 843:
      if (lookahead == 'p') ADVANCE(793);
      END_STATE();
    case 844:
      if (lookahead == 'p') ADVANCE(794);
      END_STATE();
    case 845:
      if (lookahead == 'p') ADVANCE(1080);
      END_STATE();
    case 846:
      if (lookahead == 'p') ADVANCE(473);
      END_STATE();
    case 847:
      if (lookahead == 'p') ADVANCE(60);
      END_STATE();
    case 848:
      if (lookahead == 'p') ADVANCE(61);
      END_STATE();
    case 849:
      if (lookahead == 'q') ADVANCE(652);
      END_STATE();
    case 850:
      if (lookahead == 'q') ADVANCE(1096);
      END_STATE();
    case 851:
      if (lookahead == 'q') ADVANCE(1097);
      if (lookahead == 's') ADVANCE(839);
      END_STATE();
    case 852:
      if (lookahead == 'q') ADVANCE(1098);
      END_STATE();
    case 853:
      if (lookahead == 'q') ADVANCE(1098);
      if (lookahead == 's') ADVANCE(841);
      END_STATE();
    case 854:
      if (lookahead == 'q') ADVANCE(1099);
      if (lookahead == 's') ADVANCE(842);
      END_STATE();
    case 855:
      if (lookahead == 'q') ADVANCE(1100);
      if (lookahead == 's') ADVANCE(843);
      END_STATE();
    case 856:
      if (lookahead == 'q') ADVANCE(1101);
      if (lookahead == 's') ADVANCE(844);
      END_STATE();
    case 857:
      if (lookahead == 'q') ADVANCE(653);
      END_STATE();
    case 858:
      if (lookahead == 'r') ADVANCE(211);
      END_STATE();
    case 859:
      if (lookahead == 'r') ADVANCE(1245);
      END_STATE();
    case 860:
      if (lookahead == 'r') ADVANCE(481);
      END_STATE();
    case 861:
      if (lookahead == 'r') ADVANCE(1417);
      END_STATE();
    case 862:
      if (lookahead == 'r') ADVANCE(1164);
      END_STATE();
    case 863:
      if (lookahead == 'r') ADVANCE(1319);
      END_STATE();
    case 864:
      if (lookahead == 'r') ADVANCE(1356);
      END_STATE();
    case 865:
      if (lookahead == 'r') ADVANCE(1391);
      END_STATE();
    case 866:
      if (lookahead == 'r') ADVANCE(1393);
      END_STATE();
    case 867:
      if (lookahead == 'r') ADVANCE(1331);
      END_STATE();
    case 868:
      if (lookahead == 'r') ADVANCE(1243);
      END_STATE();
    case 869:
      if (lookahead == 'r') ADVANCE(1392);
      END_STATE();
    case 870:
      if (lookahead == 'r') ADVANCE(1317);
      END_STATE();
    case 871:
      if (lookahead == 'r') ADVANCE(1235);
      END_STATE();
    case 872:
      if (lookahead == 'r') ADVANCE(1394);
      END_STATE();
    case 873:
      if (lookahead == 'r') ADVANCE(1241);
      END_STATE();
    case 874:
      if (lookahead == 'r') ADVANCE(1346);
      END_STATE();
    case 875:
      if (lookahead == 'r') ADVANCE(1104);
      END_STATE();
    case 876:
      if (lookahead == 'r') ADVANCE(526);
      END_STATE();
    case 877:
      if (lookahead == 'r') ADVANCE(953);
      END_STATE();
    case 878:
      if (lookahead == 'r') ADVANCE(741);
      END_STATE();
    case 879:
      if (lookahead == 'r') ADVANCE(752);
      END_STATE();
    case 880:
      if (lookahead == 'r') ADVANCE(824);
      END_STATE();
    case 881:
      if (lookahead == 'r') ADVANCE(276);
      END_STATE();
    case 882:
      if (lookahead == 'r') ADVANCE(1068);
      END_STATE();
    case 883:
      if (lookahead == 'r') ADVANCE(559);
      END_STATE();
    case 884:
      if (lookahead == 'r') ADVANCE(540);
      END_STATE();
    case 885:
      if (lookahead == 'r') ADVANCE(355);
      END_STATE();
    case 886:
      if (lookahead == 'r') ADVANCE(528);
      END_STATE();
    case 887:
      if (lookahead == 'r') ADVANCE(418);
      END_STATE();
    case 888:
      if (lookahead == 'r') ADVANCE(538);
      END_STATE();
    case 889:
      if (lookahead == 'r') ADVANCE(781);
      END_STATE();
    case 890:
      if (lookahead == 'r') ADVANCE(730);
      END_STATE();
    case 891:
      if (lookahead == 'r') ADVANCE(366);
      END_STATE();
    case 892:
      if (lookahead == 'r') ADVANCE(949);
      END_STATE();
    case 893:
      if (lookahead == 'r') ADVANCE(318);
      END_STATE();
    case 894:
      if (lookahead == 'r') ADVANCE(321);
      END_STATE();
    case 895:
      if (lookahead == 'r') ADVANCE(462);
      END_STATE();
    case 896:
      if (lookahead == 'r') ADVANCE(440);
      END_STATE();
    case 897:
      if (lookahead == 'r') ADVANCE(413);
      END_STATE();
    case 898:
      if (lookahead == 'r') ADVANCE(408);
      END_STATE();
    case 899:
      if (lookahead == 'r') ADVANCE(459);
      END_STATE();
    case 900:
      if (lookahead == 'r') ADVANCE(748);
      END_STATE();
    case 901:
      if (lookahead == 'r') ADVANCE(243);
      END_STATE();
    case 902:
      if (lookahead == 'r') ADVANCE(227);
      END_STATE();
    case 903:
      if (lookahead == 'r') ADVANCE(667);
      END_STATE();
    case 904:
      if (lookahead == 'r') ADVANCE(547);
      END_STATE();
    case 905:
      if (lookahead == 'r') ADVANCE(771);
      END_STATE();
    case 906:
      if (lookahead == 'r') ADVANCE(166);
      END_STATE();
    case 907:
      if (lookahead == 'r') ADVANCE(1107);
      END_STATE();
    case 908:
      if (lookahead == 'r') ADVANCE(659);
      END_STATE();
    case 909:
      if (lookahead == 'r') ADVANCE(376);
      END_STATE();
    case 910:
      if (lookahead == 'r') ADVANCE(1050);
      END_STATE();
    case 911:
      if (lookahead == 'r') ADVANCE(1108);
      END_STATE();
    case 912:
      if (lookahead == 'r') ADVANCE(380);
      END_STATE();
    case 913:
      if (lookahead == 'r') ADVANCE(58);
      END_STATE();
    case 914:
      if (lookahead == 'r') ADVANCE(551);
      END_STATE();
    case 915:
      if (lookahead == 'r') ADVANCE(1109);
      END_STATE();
    case 916:
      if (lookahead == 'r') ADVANCE(768);
      END_STATE();
    case 917:
      if (lookahead == 'r') ADVANCE(1111);
      END_STATE();
    case 918:
      if (lookahead == 'r') ADVANCE(916);
      END_STATE();
    case 919:
      if (lookahead == 'r') ADVANCE(830);
      END_STATE();
    case 920:
      if (lookahead == 'r') ADVANCE(668);
      END_STATE();
    case 921:
      if (lookahead == 'r') ADVANCE(432);
      END_STATE();
    case 922:
      if (lookahead == 'r') ADVANCE(432);
      if (lookahead == 's') ADVANCE(56);
      END_STATE();
    case 923:
      if (lookahead == 'r') ADVANCE(836);
      END_STATE();
    case 924:
      if (lookahead == 'r') ADVANCE(262);
      END_STATE();
    case 925:
      if (lookahead == 'r') ADVANCE(994);
      END_STATE();
    case 926:
      if (lookahead == 'r') ADVANCE(995);
      END_STATE();
    case 927:
      if (lookahead == 'r') ADVANCE(998);
      END_STATE();
    case 928:
      if (lookahead == 'r') ADVANCE(474);
      END_STATE();
    case 929:
      if (lookahead == 'r') ADVANCE(477);
      END_STATE();
    case 930:
      if (lookahead == 's') ADVANCE(164);
      END_STATE();
    case 931:
      if (lookahead == 's') ADVANCE(849);
      END_STATE();
    case 932:
      if (lookahead == 's') ADVANCE(1299);
      END_STATE();
    case 933:
      if (lookahead == 's') ADVANCE(1445);
      END_STATE();
    case 934:
      if (lookahead == 's') ADVANCE(1273);
      END_STATE();
    case 935:
      if (lookahead == 's') ADVANCE(1181);
      END_STATE();
    case 936:
      if (lookahead == 's') ADVANCE(1400);
      END_STATE();
    case 937:
      if (lookahead == 's') ADVANCE(1265);
      END_STATE();
    case 938:
      if (lookahead == 's') ADVANCE(1324);
      END_STATE();
    case 939:
      if (lookahead == 's') ADVANCE(1339);
      END_STATE();
    case 940:
      if (lookahead == 's') ADVANCE(1154);
      END_STATE();
    case 941:
      if (lookahead == 's') ADVANCE(1336);
      END_STATE();
    case 942:
      if (lookahead == 's') ADVANCE(1158);
      END_STATE();
    case 943:
      if (lookahead == 's') ADVANCE(1233);
      END_STATE();
    case 944:
      if (lookahead == 's') ADVANCE(1386);
      END_STATE();
    case 945:
      if (lookahead == 's') ADVANCE(1360);
      END_STATE();
    case 946:
      if (lookahead == 's') ADVANCE(1249);
      END_STATE();
    case 947:
      if (lookahead == 's') ADVANCE(1351);
      END_STATE();
    case 948:
      if (lookahead == 's') ADVANCE(1349);
      END_STATE();
    case 949:
      if (lookahead == 's') ADVANCE(1352);
      END_STATE();
    case 950:
      if (lookahead == 's') ADVANCE(56);
      END_STATE();
    case 951:
      if (lookahead == 's') ADVANCE(505);
      END_STATE();
    case 952:
      if (lookahead == 's') ADVANCE(501);
      END_STATE();
    case 953:
      if (lookahead == 's') ADVANCE(553);
      END_STATE();
    case 954:
      if (lookahead == 's') ADVANCE(933);
      END_STATE();
    case 955:
      if (lookahead == 's') ADVANCE(934);
      END_STATE();
    case 956:
      if (lookahead == 's') ADVANCE(1061);
      END_STATE();
    case 957:
      if (lookahead == 's') ADVANCE(817);
      END_STATE();
    case 958:
      if (lookahead == 's') ADVANCE(937);
      END_STATE();
    case 959:
      if (lookahead == 's') ADVANCE(529);
      END_STATE();
    case 960:
      if (lookahead == 's') ADVANCE(195);
      END_STATE();
    case 961:
      if (lookahead == 's') ADVANCE(943);
      END_STATE();
    case 962:
      if (lookahead == 's') ADVANCE(1011);
      END_STATE();
    case 963:
      if (lookahead == 's') ADVANCE(1012);
      END_STATE();
    case 964:
      if (lookahead == 's') ADVANCE(1049);
      END_STATE();
    case 965:
      if (lookahead == 's') ADVANCE(1015);
      END_STATE();
    case 966:
      if (lookahead == 's') ADVANCE(378);
      END_STATE();
    case 967:
      if (lookahead == 's') ADVANCE(1021);
      END_STATE();
    case 968:
      if (lookahead == 's') ADVANCE(320);
      END_STATE();
    case 969:
      if (lookahead == 's') ADVANCE(1023);
      END_STATE();
    case 970:
      if (lookahead == 's') ADVANCE(1024);
      END_STATE();
    case 971:
      if (lookahead == 's') ADVANCE(1025);
      END_STATE();
    case 972:
      if (lookahead == 's') ADVANCE(1026);
      END_STATE();
    case 973:
      if (lookahead == 's') ADVANCE(1070);
      END_STATE();
    case 974:
      if (lookahead == 's') ADVANCE(1027);
      END_STATE();
    case 975:
      if (lookahead == 's') ADVANCE(325);
      END_STATE();
    case 976:
      if (lookahead == 's') ADVANCE(1031);
      END_STATE();
    case 977:
      if (lookahead == 's') ADVANCE(327);
      END_STATE();
    case 978:
      if (lookahead == 's') ADVANCE(331);
      END_STATE();
    case 979:
      if (lookahead == 's') ADVANCE(334);
      END_STATE();
    case 980:
      if (lookahead == 's') ADVANCE(338);
      END_STATE();
    case 981:
      if (lookahead == 's') ADVANCE(339);
      END_STATE();
    case 982:
      if (lookahead == 's') ADVANCE(340);
      END_STATE();
    case 983:
      if (lookahead == 's') ADVANCE(342);
      END_STATE();
    case 984:
      if (lookahead == 's') ADVANCE(344);
      END_STATE();
    case 985:
      if (lookahead == 's') ADVANCE(345);
      END_STATE();
    case 986:
      if (lookahead == 's') ADVANCE(348);
      END_STATE();
    case 987:
      if (lookahead == 's') ADVANCE(1046);
      END_STATE();
    case 988:
      if (lookahead == 's') ADVANCE(138);
      END_STATE();
    case 989:
      if (lookahead == 's') ADVANCE(397);
      END_STATE();
    case 990:
      if (lookahead == 's') ADVANCE(825);
      END_STATE();
    case 991:
      if (lookahead == 's') ADVANCE(562);
      END_STATE();
    case 992:
      if (lookahead == 's') ADVANCE(1067);
      END_STATE();
    case 993:
      if (lookahead == 's') ADVANCE(461);
      END_STATE();
    case 994:
      if (lookahead == 's') ADVANCE(567);
      END_STATE();
    case 995:
      if (lookahead == 's') ADVANCE(570);
      END_STATE();
    case 996:
      if (lookahead == 's') ADVANCE(466);
      END_STATE();
    case 997:
      if (lookahead == 's') ADVANCE(569);
      END_STATE();
    case 998:
      if (lookahead == 's') ADVANCE(572);
      END_STATE();
    case 999:
      if (lookahead == 's') ADVANCE(172);
      END_STATE();
    case 1000:
      if (lookahead == 's') ADVANCE(997);
      END_STATE();
    case 1001:
      if (lookahead == 's') ADVANCE(857);
      END_STATE();
    case 1002:
      if (lookahead == 't') ADVANCE(499);
      END_STATE();
    case 1003:
      if (lookahead == 't') ADVANCE(1209);
      END_STATE();
    case 1004:
      if (lookahead == 't') ADVANCE(1372);
      END_STATE();
    case 1005:
      if (lookahead == 't') ADVANCE(1407);
      END_STATE();
    case 1006:
      if (lookahead == 't') ADVANCE(1389);
      END_STATE();
    case 1007:
      if (lookahead == 't') ADVANCE(1376);
      END_STATE();
    case 1008:
      if (lookahead == 't') ADVANCE(1373);
      END_STATE();
    case 1009:
      if (lookahead == 't') ADVANCE(1410);
      END_STATE();
    case 1010:
      if (lookahead == 't') ADVANCE(54);
      END_STATE();
    case 1011:
      if (lookahead == 't') ADVANCE(1325);
      END_STATE();
    case 1012:
      if (lookahead == 't') ADVANCE(1416);
      END_STATE();
    case 1013:
      if (lookahead == 't') ADVANCE(1297);
      END_STATE();
    case 1014:
      if (lookahead == 't') ADVANCE(1193);
      END_STATE();
    case 1015:
      if (lookahead == 't') ADVANCE(1156);
      END_STATE();
    case 1016:
      if (lookahead == 't') ADVANCE(1279);
      END_STATE();
    case 1017:
      if (lookahead == 't') ADVANCE(1237);
      END_STATE();
    case 1018:
      if (lookahead == 't') ADVANCE(1322);
      END_STATE();
    case 1019:
      if (lookahead == 't') ADVANCE(1271);
      END_STATE();
    case 1020:
      if (lookahead == 't') ADVANCE(1221);
      END_STATE();
    case 1021:
      if (lookahead == 't') ADVANCE(1307);
      END_STATE();
    case 1022:
      if (lookahead == 't') ADVANCE(1370);
      END_STATE();
    case 1023:
      if (lookahead == 't') ADVANCE(1301);
      END_STATE();
    case 1024:
      if (lookahead == 't') ADVANCE(1229);
      END_STATE();
    case 1025:
      if (lookahead == 't') ADVANCE(1414);
      END_STATE();
    case 1026:
      if (lookahead == 't') ADVANCE(1231);
      END_STATE();
    case 1027:
      if (lookahead == 't') ADVANCE(1362);
      END_STATE();
    case 1028:
      if (lookahead == 't') ADVANCE(1367);
      END_STATE();
    case 1029:
      if (lookahead == 't') ADVANCE(1239);
      END_STATE();
    case 1030:
      if (lookahead == 't') ADVANCE(1368);
      END_STATE();
    case 1031:
      if (lookahead == 't') ADVANCE(1334);
      END_STATE();
    case 1032:
      if (lookahead == 't') ADVANCE(1388);
      END_STATE();
    case 1033:
      if (lookahead == 't') ADVANCE(1131);
      END_STATE();
    case 1034:
      if (lookahead == 't') ADVANCE(51);
      END_STATE();
    case 1035:
      if (lookahead == 't') ADVANCE(184);
      END_STATE();
    case 1036:
      if (lookahead == 't') ADVANCE(1095);
      END_STATE();
    case 1037:
      if (lookahead == 't') ADVANCE(196);
      if (lookahead == 'x') ADVANCE(238);
      END_STATE();
    case 1038:
      if (lookahead == 't') ADVANCE(557);
      END_STATE();
    case 1039:
      if (lookahead == 't') ADVANCE(798);
      END_STATE();
    case 1040:
      if (lookahead == 't') ADVANCE(208);
      END_STATE();
    case 1041:
      if (lookahead == 't') ADVANCE(621);
      END_STATE();
    case 1042:
      if (lookahead == 't') ADVANCE(932);
      END_STATE();
    case 1043:
      if (lookahead == 't') ADVANCE(815);
      END_STATE();
    case 1044:
      if (lookahead == 't') ADVANCE(206);
      END_STATE();
    case 1045:
      if (lookahead == 't') ADVANCE(34);
      END_STATE();
    case 1046:
      if (lookahead == 't') ADVANCE(365);
      END_STATE();
    case 1047:
      if (lookahead == 't') ADVANCE(207);
      END_STATE();
    case 1048:
      if (lookahead == 't') ADVANCE(939);
      END_STATE();
    case 1049:
      if (lookahead == 't') ADVANCE(158);
      END_STATE();
    case 1050:
      if (lookahead == 't') ADVANCE(14);
      END_STATE();
    case 1051:
      if (lookahead == 't') ADVANCE(945);
      END_STATE();
    case 1052:
      if (lookahead == 't') ADVANCE(731);
      END_STATE();
    case 1053:
      if (lookahead == 't') ADVANCE(809);
      END_STATE();
    case 1054:
      if (lookahead == 't') ADVANCE(732);
      END_STATE();
    case 1055:
      if (lookahead == 't') ADVANCE(427);
      END_STATE();
    case 1056:
      if (lookahead == 't') ADVANCE(324);
      END_STATE();
    case 1057:
      if (lookahead == 't') ADVANCE(336);
      END_STATE();
    case 1058:
      if (lookahead == 't') ADVANCE(522);
      END_STATE();
    case 1059:
      if (lookahead == 't') ADVANCE(185);
      END_STATE();
    case 1060:
      if (lookahead == 't') ADVANCE(367);
      END_STATE();
    case 1061:
      if (lookahead == 't') ADVANCE(139);
      END_STATE();
    case 1062:
      if (lookahead == 't') ADVANCE(1063);
      END_STATE();
    case 1063:
      if (lookahead == 't') ADVANCE(848);
      END_STATE();
    case 1064:
      if (lookahead == 't') ADVANCE(1053);
      END_STATE();
    case 1065:
      if (lookahead == 't') ADVANCE(820);
      END_STATE();
    case 1066:
      if (lookahead == 't') ADVANCE(755);
      END_STATE();
    case 1067:
      if (lookahead == 't') ADVANCE(142);
      END_STATE();
    case 1068:
      if (lookahead == 't') ADVANCE(751);
      END_STATE();
    case 1069:
      if (lookahead == 't') ADVANCE(405);
      END_STATE();
    case 1070:
      if (lookahead == 't') ADVANCE(898);
      END_STATE();
    case 1071:
      if (lookahead == 't') ADVANCE(237);
      END_STATE();
    case 1072:
      if (lookahead == 't') ADVANCE(914);
      END_STATE();
    case 1073:
      if (lookahead == 't') ADVANCE(45);
      END_STATE();
    case 1074:
      if (lookahead == 't') ADVANCE(837);
      END_STATE();
    case 1075:
      if (lookahead == 't') ADVANCE(956);
      END_STATE();
    case 1076:
      if (lookahead == 't') ADVANCE(565);
      END_STATE();
    case 1077:
      if (lookahead == 't') ADVANCE(40);
      END_STATE();
    case 1078:
      if (lookahead == 't') ADVANCE(568);
      END_STATE();
    case 1079:
      if (lookahead == 't') ADVANCE(444);
      END_STATE();
    case 1080:
      if (lookahead == 't') ADVANCE(571);
      END_STATE();
    case 1081:
      if (lookahead == 't') ADVANCE(573);
      END_STATE();
    case 1082:
      if (lookahead == 't') ADVANCE(170);
      END_STATE();
    case 1083:
      if (lookahead == 't') ADVANCE(49);
      END_STATE();
    case 1084:
      if (lookahead == 'u') ADVANCE(416);
      END_STATE();
    case 1085:
      if (lookahead == 'u') ADVANCE(21);
      END_STATE();
    case 1086:
      if (lookahead == 'u') ADVANCE(902);
      END_STATE();
    case 1087:
      if (lookahead == 'u') ADVANCE(628);
      END_STATE();
    case 1088:
      if (lookahead == 'u') ADVANCE(799);
      END_STATE();
    case 1089:
      if (lookahead == 'u') ADVANCE(626);
      END_STATE();
    case 1090:
      if (lookahead == 'u') ADVANCE(312);
      END_STATE();
    case 1091:
      if (lookahead == 'u') ADVANCE(816);
      END_STATE();
    case 1092:
      if (lookahead == 'u') ADVANCE(1013);
      END_STATE();
    case 1093:
      if (lookahead == 'u') ADVANCE(1052);
      END_STATE();
    case 1094:
      if (lookahead == 'u') ADVANCE(341);
      END_STATE();
    case 1095:
      if (lookahead == 'u') ADVANCE(894);
      END_STATE();
    case 1096:
      if (lookahead == 'u') ADVANCE(388);
      END_STATE();
    case 1097:
      if (lookahead == 'u') ADVANCE(446);
      END_STATE();
    case 1098:
      if (lookahead == 'u') ADVANCE(449);
      END_STATE();
    case 1099:
      if (lookahead == 'u') ADVANCE(453);
      END_STATE();
    case 1100:
      if (lookahead == 'u') ADVANCE(456);
      END_STATE();
    case 1101:
      if (lookahead == 'u') ADVANCE(457);
      END_STATE();
    case 1102:
      if (lookahead == 'u') ADVANCE(1076);
      if (lookahead == 'v') ADVANCE(323);
      END_STATE();
    case 1103:
      if (lookahead == 'v') ADVANCE(1071);
      END_STATE();
    case 1104:
      if (lookahead == 'v') ADVANCE(372);
      END_STATE();
    case 1105:
      if (lookahead == 'v') ADVANCE(156);
      END_STATE();
    case 1106:
      if (lookahead == 'v') ADVANCE(382);
      END_STATE();
    case 1107:
      if (lookahead == 'v') ADVANCE(399);
      END_STATE();
    case 1108:
      if (lookahead == 'v') ADVANCE(403);
      END_STATE();
    case 1109:
      if (lookahead == 'v') ADVANCE(404);
      END_STATE();
    case 1110:
      if (lookahead == 'v') ADVANCE(393);
      END_STATE();
    case 1111:
      if (lookahead == 'v') ADVANCE(406);
      END_STATE();
    case 1112:
      if (lookahead == 'v') ADVANCE(343);
      END_STATE();
    case 1113:
      if (lookahead == 'v') ADVANCE(347);
      END_STATE();
    case 1114:
      if (lookahead == 'w') ADVANCE(1397);
      END_STATE();
    case 1115:
      if (lookahead == 'w') ADVANCE(1253);
      END_STATE();
    case 1116:
      if (lookahead == 'w') ADVANCE(1259);
      END_STATE();
    case 1117:
      if (lookahead == 'w') ADVANCE(11);
      END_STATE();
    case 1118:
      if (lookahead == 'x') ADVANCE(238);
      END_STATE();
    case 1119:
      if (lookahead == 'x') ADVANCE(1126);
      END_STATE();
    case 1120:
      if (lookahead == 'x') ADVANCE(1130);
      END_STATE();
    case 1121:
      if (lookahead == 'y') ADVANCE(1396);
      END_STATE();
    case 1122:
      if (lookahead == 'y') ADVANCE(1257);
      END_STATE();
    case 1123:
      if (lookahead == 'y') ADVANCE(1285);
      END_STATE();
    case 1124:
      if (lookahead == 'y') ADVANCE(1263);
      END_STATE();
    case 1125:
      if (lookahead == 'y') ADVANCE(1289);
      END_STATE();
    case 1126:
      if (lookahead == 'y') ADVANCE(1348);
      END_STATE();
    case 1127:
      if (lookahead == 'y') ADVANCE(1343);
      END_STATE();
    case 1128:
      if (lookahead == 'y') ADVANCE(1411);
      END_STATE();
    case 1129:
      if (lookahead == 'y') ADVANCE(931);
      END_STATE();
    case 1130:
      if (lookahead == 'y') ADVANCE(35);
      END_STATE();
    case 1131:
      if (lookahead == 'y') ADVANCE(822);
      END_STATE();
    case 1132:
      if (lookahead == 'z') ADVANCE(346);
      END_STATE();
    case 1133:
      if (lookahead == '|') ADVANCE(1441);
      END_STATE();
    case 1134:
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(1429);
      END_STATE();
    case 1135:
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(1424);
      END_STATE();
    case 1136:
      if (lookahead != 0 &&
          lookahead != ']') ADVANCE(85);
      END_STATE();
    case 1137:
      if (eof) ADVANCE(1140);
      if (lookahead == '!') ADVANCE(1442);
      if (lookahead == '"') ADVANCE(2);
      if (lookahead == '#') ADVANCE(1141);
      if (lookahead == '%') ADVANCE(84);
      if (lookahead == '*') ADVANCE(79);
      if (lookahead == '/') ADVANCE(1905);
      if (lookahead == '2') ADVANCE(1430);
      if (lookahead == 'a') ADVANCE(1511);
      if (lookahead == 'b') ADVANCE(1466);
      if (lookahead == 'c') ADVANCE(1467);
      if (lookahead == 'd') ADVANCE(1471);
      if (lookahead == 'e') ADVANCE(1694);
      if (lookahead == 'f') ADVANCE(1719);
      if (lookahead == 'g') ADVANCE(1673);
      if (lookahead == 'h') ADVANCE(1472);
      if (lookahead == 'i') ADVANCE(1529);
      if (lookahead == 'l') ADVANCE(1637);
      if (lookahead == 'm') ADVANCE(1468);
      if (lookahead == 'n') ADVANCE(1469);
      if (lookahead == 'o') ADVANCE(1754);
      if (lookahead == 'p') ADVANCE(1549);
      if (lookahead == 'r') ADVANCE(1477);
      if (lookahead == 's') ADVANCE(1574);
      if (lookahead == 't') ADVANCE(1515);
      if (lookahead == 'u') ADVANCE(1695);
      if (lookahead == '|') ADVANCE(1133);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(1434);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(1137)
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(1433);
      if (('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('j' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1138:
      if (eof) ADVANCE(1140);
      if (lookahead == '#') ADVANCE(1141);
      if (lookahead == 'a') ADVANCE(223);
      if (lookahead == 'b') ADVANCE(102);
      if (lookahead == 'c') ADVANCE(90);
      if (lookahead == 'd') ADVANCE(92);
      if (lookahead == 'e') ADVANCE(728);
      if (lookahead == 'f') ADVANCE(787);
      if (lookahead == 'g') ADVANCE(617);
      if (lookahead == 'h') ADVANCE(105);
      if (lookahead == 'i') ADVANCE(264);
      if (lookahead == 'l') ADVANCE(532);
      if (lookahead == 'm') ADVANCE(107);
      if (lookahead == 'n') ADVANCE(94);
      if (lookahead == 'o') ADVANCE(810);
      if (lookahead == 'p') ADVANCE(351);
      if (lookahead == 'r') ADVANCE(115);
      if (lookahead == 's') ADVANCE(424);
      if (lookahead == 't') ADVANCE(261);
      if (lookahead == 'u') ADVANCE(700);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(1138)
      END_STATE();
    case 1139:
      if (eof) ADVANCE(1140);
      if (lookahead == '#') ADVANCE(1141);
      if (lookahead == 'a') ADVANCE(1511);
      if (lookahead == 'b') ADVANCE(1466);
      if (lookahead == 'c') ADVANCE(1467);
      if (lookahead == 'd') ADVANCE(1471);
      if (lookahead == 'e') ADVANCE(1694);
      if (lookahead == 'f') ADVANCE(1719);
      if (lookahead == 'g') ADVANCE(1673);
      if (lookahead == 'h') ADVANCE(1472);
      if (lookahead == 'i') ADVANCE(1530);
      if (lookahead == 'l') ADVANCE(1637);
      if (lookahead == 'm') ADVANCE(1468);
      if (lookahead == 'n') ADVANCE(1469);
      if (lookahead == 'o') ADVANCE(1755);
      if (lookahead == 'p') ADVANCE(1549);
      if (lookahead == 'r') ADVANCE(1478);
      if (lookahead == 's') ADVANCE(1574);
      if (lookahead == 't') ADVANCE(1515);
      if (lookahead == 'u') ADVANCE(1709);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(1139)
      if (('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('j' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1140:
      ACCEPT_TOKEN(ts_builtin_sym_end);
      END_STATE();
    case 1141:
      ACCEPT_TOKEN(sym_comment);
      if (lookahead != 0 &&
          lookahead != '\n') ADVANCE(1141);
      END_STATE();
    case 1142:
      ACCEPT_TOKEN(anon_sym_global);
      END_STATE();
    case 1143:
      ACCEPT_TOKEN(anon_sym_global);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1144:
      ACCEPT_TOKEN(anon_sym_defaults);
      END_STATE();
    case 1145:
      ACCEPT_TOKEN(anon_sym_defaults);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1146:
      ACCEPT_TOKEN(anon_sym_frontend);
      END_STATE();
    case 1147:
      ACCEPT_TOKEN(anon_sym_frontend);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1148:
      ACCEPT_TOKEN(anon_sym_backend);
      END_STATE();
    case 1149:
      ACCEPT_TOKEN(anon_sym_backend);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1150:
      ACCEPT_TOKEN(anon_sym_listen);
      END_STATE();
    case 1151:
      ACCEPT_TOKEN(anon_sym_listen);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1152:
      ACCEPT_TOKEN(anon_sym_peers);
      END_STATE();
    case 1153:
      ACCEPT_TOKEN(anon_sym_peers);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1154:
      ACCEPT_TOKEN(anon_sym_resolvers);
      END_STATE();
    case 1155:
      ACCEPT_TOKEN(anon_sym_resolvers);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1156:
      ACCEPT_TOKEN(anon_sym_userlist);
      END_STATE();
    case 1157:
      ACCEPT_TOKEN(anon_sym_userlist);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1158:
      ACCEPT_TOKEN(anon_sym_aggregations);
      END_STATE();
    case 1159:
      ACCEPT_TOKEN(anon_sym_aggregations);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1160:
      ACCEPT_TOKEN(anon_sym_acl);
      END_STATE();
    case 1161:
      ACCEPT_TOKEN(anon_sym_acl);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1162:
      ACCEPT_TOKEN(anon_sym_bind);
      if (lookahead == '-') ADVANCE(1764);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1163:
      ACCEPT_TOKEN(anon_sym_bind);
      if (lookahead == '-') ADVANCE(826);
      END_STATE();
    case 1164:
      ACCEPT_TOKEN(anon_sym_server);
      END_STATE();
    case 1165:
      ACCEPT_TOKEN(anon_sym_server);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1166:
      ACCEPT_TOKEN(anon_sym_balance);
      END_STATE();
    case 1167:
      ACCEPT_TOKEN(anon_sym_balance);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1168:
      ACCEPT_TOKEN(anon_sym_mode);
      END_STATE();
    case 1169:
      ACCEPT_TOKEN(anon_sym_mode);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1170:
      ACCEPT_TOKEN(anon_sym_maxconn);
      END_STATE();
    case 1171:
      ACCEPT_TOKEN(anon_sym_maxconn);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1172:
      ACCEPT_TOKEN(anon_sym_user);
      if (lookahead == 'l') ADVANCE(1648);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1173:
      ACCEPT_TOKEN(anon_sym_user);
      if (lookahead == 'l') ADVANCE(560);
      END_STATE();
    case 1174:
      ACCEPT_TOKEN(anon_sym_group);
      END_STATE();
    case 1175:
      ACCEPT_TOKEN(anon_sym_group);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1176:
      ACCEPT_TOKEN(anon_sym_daemon);
      END_STATE();
    case 1177:
      ACCEPT_TOKEN(anon_sym_daemon);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1178:
      ACCEPT_TOKEN(anon_sym_log);
      if (lookahead == '-') ADVANCE(483);
      END_STATE();
    case 1179:
      ACCEPT_TOKEN(anon_sym_log);
      if (lookahead == '-') ADVANCE(1624);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1180:
      ACCEPT_TOKEN(anon_sym_log);
      if (lookahead == '-') ADVANCE(482);
      END_STATE();
    case 1181:
      ACCEPT_TOKEN(anon_sym_retries);
      END_STATE();
    case 1182:
      ACCEPT_TOKEN(anon_sym_retries);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1183:
      ACCEPT_TOKEN(anon_sym_cookie);
      END_STATE();
    case 1184:
      ACCEPT_TOKEN(anon_sym_cookie);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1185:
      ACCEPT_TOKEN(anon_sym_errorfile);
      END_STATE();
    case 1186:
      ACCEPT_TOKEN(anon_sym_errorfile);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1187:
      ACCEPT_TOKEN(anon_sym_default_backend);
      END_STATE();
    case 1188:
      ACCEPT_TOKEN(anon_sym_default_backend);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1189:
      ACCEPT_TOKEN(anon_sym_use_backend);
      END_STATE();
    case 1190:
      ACCEPT_TOKEN(anon_sym_use_backend);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1191:
      ACCEPT_TOKEN(anon_sym_compression);
      END_STATE();
    case 1192:
      ACCEPT_TOKEN(anon_sym_compression);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1193:
      ACCEPT_TOKEN(anon_sym_redirect);
      END_STATE();
    case 1194:
      ACCEPT_TOKEN(anon_sym_redirect);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1195:
      ACCEPT_TOKEN(anon_sym_source);
      END_STATE();
    case 1196:
      ACCEPT_TOKEN(anon_sym_source);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1197:
      ACCEPT_TOKEN(anon_sym_id);
      END_STATE();
    case 1198:
      ACCEPT_TOKEN(anon_sym_id);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1199:
      ACCEPT_TOKEN(anon_sym_disabled);
      END_STATE();
    case 1200:
      ACCEPT_TOKEN(anon_sym_disabled);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1201:
      ACCEPT_TOKEN(anon_sym_enabled);
      END_STATE();
    case 1202:
      ACCEPT_TOKEN(anon_sym_enabled);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1203:
      ACCEPT_TOKEN(anon_sym_dispatch);
      END_STATE();
    case 1204:
      ACCEPT_TOKEN(anon_sym_dispatch);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1205:
      ACCEPT_TOKEN(anon_sym_backlog);
      END_STATE();
    case 1206:
      ACCEPT_TOKEN(anon_sym_backlog);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1207:
      ACCEPT_TOKEN(anon_sym_description);
      END_STATE();
    case 1208:
      ACCEPT_TOKEN(anon_sym_description);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1209:
      ACCEPT_TOKEN(anon_sym_chroot);
      END_STATE();
    case 1210:
      ACCEPT_TOKEN(anon_sym_chroot);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1211:
      ACCEPT_TOKEN(anon_sym_ca_DASHbase);
      END_STATE();
    case 1212:
      ACCEPT_TOKEN(anon_sym_ca_DASHbase);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1213:
      ACCEPT_TOKEN(anon_sym_crt_DASHbase);
      END_STATE();
    case 1214:
      ACCEPT_TOKEN(anon_sym_crt_DASHbase);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1215:
      ACCEPT_TOKEN(anon_sym_nbproc);
      END_STATE();
    case 1216:
      ACCEPT_TOKEN(anon_sym_nbproc);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1217:
      ACCEPT_TOKEN(anon_sym_cpu_DASHmap);
      END_STATE();
    case 1218:
      ACCEPT_TOKEN(anon_sym_cpu_DASHmap);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1219:
      ACCEPT_TOKEN(anon_sym_lua_DASHload);
      END_STATE();
    case 1220:
      ACCEPT_TOKEN(anon_sym_lua_DASHload);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1221:
      ACCEPT_TOKEN(anon_sym_monitor_DASHnet);
      END_STATE();
    case 1222:
      ACCEPT_TOKEN(anon_sym_monitor_DASHnet);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1223:
      ACCEPT_TOKEN(anon_sym_monitor_DASHuri);
      END_STATE();
    case 1224:
      ACCEPT_TOKEN(anon_sym_monitor_DASHuri);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1225:
      ACCEPT_TOKEN(anon_sym_grace);
      END_STATE();
    case 1226:
      ACCEPT_TOKEN(anon_sym_grace);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1227:
      ACCEPT_TOKEN(anon_sym_hash_DASHtype);
      END_STATE();
    case 1228:
      ACCEPT_TOKEN(anon_sym_hash_DASHtype);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1229:
      ACCEPT_TOKEN(anon_sym_force_DASHpersist);
      END_STATE();
    case 1230:
      ACCEPT_TOKEN(anon_sym_force_DASHpersist);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1231:
      ACCEPT_TOKEN(anon_sym_ignore_DASHpersist);
      END_STATE();
    case 1232:
      ACCEPT_TOKEN(anon_sym_ignore_DASHpersist);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1233:
      ACCEPT_TOKEN(anon_sym_bind_DASHprocess);
      END_STATE();
    case 1234:
      ACCEPT_TOKEN(anon_sym_bind_DASHprocess);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1235:
      ACCEPT_TOKEN(anon_sym_default_DASHserver);
      END_STATE();
    case 1236:
      ACCEPT_TOKEN(anon_sym_default_DASHserver);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1237:
      ACCEPT_TOKEN(anon_sym_log_DASHformat);
      END_STATE();
    case 1238:
      ACCEPT_TOKEN(anon_sym_log_DASHformat);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1239:
      ACCEPT_TOKEN(anon_sym_unique_DASHid_DASHformat);
      END_STATE();
    case 1240:
      ACCEPT_TOKEN(anon_sym_unique_DASHid_DASHformat);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1241:
      ACCEPT_TOKEN(anon_sym_unique_DASHid_DASHheader);
      END_STATE();
    case 1242:
      ACCEPT_TOKEN(anon_sym_unique_DASHid_DASHheader);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1243:
      ACCEPT_TOKEN(anon_sym_nameserver);
      END_STATE();
    case 1244:
      ACCEPT_TOKEN(anon_sym_nameserver);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1245:
      ACCEPT_TOKEN(anon_sym_peer);
      if (lookahead == 's') ADVANCE(1152);
      END_STATE();
    case 1246:
      ACCEPT_TOKEN(anon_sym_peer);
      if (lookahead == 's') ADVANCE(1153);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1247:
      ACCEPT_TOKEN(anon_sym_resolution_pool_size);
      END_STATE();
    case 1248:
      ACCEPT_TOKEN(anon_sym_resolution_pool_size);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1249:
      ACCEPT_TOKEN(anon_sym_resolve_retries);
      END_STATE();
    case 1250:
      ACCEPT_TOKEN(anon_sym_resolve_retries);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1251:
      ACCEPT_TOKEN(anon_sym_reqadd);
      END_STATE();
    case 1252:
      ACCEPT_TOKEN(anon_sym_reqadd);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1253:
      ACCEPT_TOKEN(anon_sym_reqallow);
      END_STATE();
    case 1254:
      ACCEPT_TOKEN(anon_sym_reqallow);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1255:
      ACCEPT_TOKEN(anon_sym_reqdel);
      END_STATE();
    case 1256:
      ACCEPT_TOKEN(anon_sym_reqdel);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1257:
      ACCEPT_TOKEN(anon_sym_reqdeny);
      END_STATE();
    case 1258:
      ACCEPT_TOKEN(anon_sym_reqdeny);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1259:
      ACCEPT_TOKEN(anon_sym_reqiallow);
      END_STATE();
    case 1260:
      ACCEPT_TOKEN(anon_sym_reqiallow);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1261:
      ACCEPT_TOKEN(anon_sym_reqidel);
      END_STATE();
    case 1262:
      ACCEPT_TOKEN(anon_sym_reqidel);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1263:
      ACCEPT_TOKEN(anon_sym_reqideny);
      END_STATE();
    case 1264:
      ACCEPT_TOKEN(anon_sym_reqideny);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1265:
      ACCEPT_TOKEN(anon_sym_reqipass);
      END_STATE();
    case 1266:
      ACCEPT_TOKEN(anon_sym_reqipass);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1267:
      ACCEPT_TOKEN(anon_sym_reqirep);
      END_STATE();
    case 1268:
      ACCEPT_TOKEN(anon_sym_reqirep);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1269:
      ACCEPT_TOKEN(anon_sym_reqisetbe);
      END_STATE();
    case 1270:
      ACCEPT_TOKEN(anon_sym_reqisetbe);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1271:
      ACCEPT_TOKEN(anon_sym_reqitarpit);
      END_STATE();
    case 1272:
      ACCEPT_TOKEN(anon_sym_reqitarpit);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1273:
      ACCEPT_TOKEN(anon_sym_reqpass);
      END_STATE();
    case 1274:
      ACCEPT_TOKEN(anon_sym_reqpass);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1275:
      ACCEPT_TOKEN(anon_sym_reqrep);
      END_STATE();
    case 1276:
      ACCEPT_TOKEN(anon_sym_reqrep);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1277:
      ACCEPT_TOKEN(anon_sym_reqsetbe);
      END_STATE();
    case 1278:
      ACCEPT_TOKEN(anon_sym_reqsetbe);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1279:
      ACCEPT_TOKEN(anon_sym_reqtarpit);
      END_STATE();
    case 1280:
      ACCEPT_TOKEN(anon_sym_reqtarpit);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1281:
      ACCEPT_TOKEN(anon_sym_rspadd);
      END_STATE();
    case 1282:
      ACCEPT_TOKEN(anon_sym_rspadd);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1283:
      ACCEPT_TOKEN(anon_sym_rspdel);
      END_STATE();
    case 1284:
      ACCEPT_TOKEN(anon_sym_rspdel);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1285:
      ACCEPT_TOKEN(anon_sym_rspdeny);
      END_STATE();
    case 1286:
      ACCEPT_TOKEN(anon_sym_rspdeny);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1287:
      ACCEPT_TOKEN(anon_sym_rspidel);
      END_STATE();
    case 1288:
      ACCEPT_TOKEN(anon_sym_rspidel);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1289:
      ACCEPT_TOKEN(anon_sym_rspideny);
      END_STATE();
    case 1290:
      ACCEPT_TOKEN(anon_sym_rspideny);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1291:
      ACCEPT_TOKEN(anon_sym_rspirep);
      END_STATE();
    case 1292:
      ACCEPT_TOKEN(anon_sym_rspirep);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1293:
      ACCEPT_TOKEN(anon_sym_rsprep);
      END_STATE();
    case 1294:
      ACCEPT_TOKEN(anon_sym_rsprep);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1295:
      ACCEPT_TOKEN(anon_sym_option);
      END_STATE();
    case 1296:
      ACCEPT_TOKEN(anon_sym_option);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1297:
      ACCEPT_TOKEN(anon_sym_timeout);
      END_STATE();
    case 1298:
      ACCEPT_TOKEN(anon_sym_timeout);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1299:
      ACCEPT_TOKEN(anon_sym_stats);
      END_STATE();
    case 1300:
      ACCEPT_TOKEN(anon_sym_stats);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1301:
      ACCEPT_TOKEN(anon_sym_http_DASHrequest);
      END_STATE();
    case 1302:
      ACCEPT_TOKEN(anon_sym_http_DASHrequest);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1303:
      ACCEPT_TOKEN(anon_sym_http_DASHresponse);
      END_STATE();
    case 1304:
      ACCEPT_TOKEN(anon_sym_http_DASHresponse);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1305:
      ACCEPT_TOKEN(anon_sym_http_DASHcheck);
      END_STATE();
    case 1306:
      ACCEPT_TOKEN(anon_sym_http_DASHcheck);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1307:
      ACCEPT_TOKEN(anon_sym_tcp_DASHrequest);
      END_STATE();
    case 1308:
      ACCEPT_TOKEN(anon_sym_tcp_DASHrequest);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1309:
      ACCEPT_TOKEN(anon_sym_tcp_DASHresponse);
      END_STATE();
    case 1310:
      ACCEPT_TOKEN(anon_sym_tcp_DASHresponse);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1311:
      ACCEPT_TOKEN(anon_sym_stick);
      if (lookahead == '-') ADVANCE(1875);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1312:
      ACCEPT_TOKEN(anon_sym_stick);
      if (lookahead == '-') ADVANCE(1082);
      END_STATE();
    case 1313:
      ACCEPT_TOKEN(anon_sym_stick_DASHtable);
      END_STATE();
    case 1314:
      ACCEPT_TOKEN(anon_sym_stick_DASHtable);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1315:
      ACCEPT_TOKEN(anon_sym_capture);
      END_STATE();
    case 1316:
      ACCEPT_TOKEN(anon_sym_capture);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1317:
      ACCEPT_TOKEN(anon_sym_use_DASHserver);
      END_STATE();
    case 1318:
      ACCEPT_TOKEN(anon_sym_use_DASHserver);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1319:
      ACCEPT_TOKEN(anon_sym_monitor);
      if (lookahead == '-') ADVANCE(709);
      END_STATE();
    case 1320:
      ACCEPT_TOKEN(anon_sym_monitor);
      if (lookahead == '-') ADVANCE(1712);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1321:
      ACCEPT_TOKEN(anon_sym_fail);
      END_STATE();
    case 1322:
      ACCEPT_TOKEN(anon_sym_rate_DASHlimit);
      END_STATE();
    case 1323:
      ACCEPT_TOKEN(anon_sym_rate_DASHlimit);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1324:
      ACCEPT_TOKEN(anon_sym_sessions);
      END_STATE();
    case 1325:
      ACCEPT_TOKEN(anon_sym_persist);
      END_STATE();
    case 1326:
      ACCEPT_TOKEN(anon_sym_persist);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1327:
      ACCEPT_TOKEN(anon_sym_rdp_DASHcookie);
      END_STATE();
    case 1328:
      ACCEPT_TOKEN(anon_sym_httplog);
      END_STATE();
    case 1329:
      ACCEPT_TOKEN(anon_sym_tcplog);
      END_STATE();
    case 1330:
      ACCEPT_TOKEN(anon_sym_httpchk);
      END_STATE();
    case 1331:
      ACCEPT_TOKEN(anon_sym_forwardfor);
      END_STATE();
    case 1332:
      ACCEPT_TOKEN(anon_sym_redispatch);
      END_STATE();
    case 1333:
      ACCEPT_TOKEN(anon_sym_abortonclose);
      END_STATE();
    case 1334:
      ACCEPT_TOKEN(anon_sym_accept_DASHinvalid_DASHhttp_DASHrequest);
      END_STATE();
    case 1335:
      ACCEPT_TOKEN(anon_sym_accept_DASHinvalid_DASHhttp_DASHresponse);
      END_STATE();
    case 1336:
      ACCEPT_TOKEN(anon_sym_allbackups);
      END_STATE();
    case 1337:
      ACCEPT_TOKEN(anon_sym_checkcache);
      END_STATE();
    case 1338:
      ACCEPT_TOKEN(anon_sym_clitcpka);
      END_STATE();
    case 1339:
      ACCEPT_TOKEN(anon_sym_contstats);
      END_STATE();
    case 1340:
      ACCEPT_TOKEN(anon_sym_dontlog_DASHnormal);
      END_STATE();
    case 1341:
      ACCEPT_TOKEN(anon_sym_dontlognull);
      END_STATE();
    case 1342:
      ACCEPT_TOKEN(anon_sym_forceclose);
      END_STATE();
    case 1343:
      ACCEPT_TOKEN(anon_sym_http_DASHno_DASHdelay);
      END_STATE();
    case 1344:
      ACCEPT_TOKEN(anon_sym_http_DASHpretend_DASHkeepalive);
      END_STATE();
    case 1345:
      ACCEPT_TOKEN(anon_sym_http_DASHserver_DASHclose);
      END_STATE();
    case 1346:
      ACCEPT_TOKEN(anon_sym_http_DASHuse_DASHproxy_DASHheader);
      END_STATE();
    case 1347:
      ACCEPT_TOKEN(anon_sym_httpclose);
      END_STATE();
    case 1348:
      ACCEPT_TOKEN(anon_sym_http_proxy);
      END_STATE();
    case 1349:
      ACCEPT_TOKEN(anon_sym_independent_DASHstreams);
      END_STATE();
    case 1350:
      ACCEPT_TOKEN(anon_sym_ldap_DASHcheck);
      END_STATE();
    case 1351:
      ACCEPT_TOKEN(anon_sym_log_DASHhealth_DASHchecks);
      END_STATE();
    case 1352:
      ACCEPT_TOKEN(anon_sym_log_DASHseparate_DASHerrors);
      END_STATE();
    case 1353:
      ACCEPT_TOKEN(anon_sym_logasap);
      END_STATE();
    case 1354:
      ACCEPT_TOKEN(anon_sym_mysql_DASHcheck);
      END_STATE();
    case 1355:
      ACCEPT_TOKEN(anon_sym_pgsql_DASHcheck);
      END_STATE();
    case 1356:
      ACCEPT_TOKEN(anon_sym_nolinger);
      END_STATE();
    case 1357:
      ACCEPT_TOKEN(anon_sym_originalto);
      END_STATE();
    case 1358:
      ACCEPT_TOKEN(anon_sym_redis_DASHcheck);
      END_STATE();
    case 1359:
      ACCEPT_TOKEN(anon_sym_smtpchk);
      END_STATE();
    case 1360:
      ACCEPT_TOKEN(anon_sym_socket_DASHstats);
      END_STATE();
    case 1361:
      ACCEPT_TOKEN(anon_sym_splice_DASHauto);
      END_STATE();
    case 1362:
      ACCEPT_TOKEN(anon_sym_splice_DASHrequest);
      END_STATE();
    case 1363:
      ACCEPT_TOKEN(anon_sym_splice_DASHresponse);
      END_STATE();
    case 1364:
      ACCEPT_TOKEN(anon_sym_srvtcpka);
      END_STATE();
    case 1365:
      ACCEPT_TOKEN(anon_sym_ssl_DASHhello_DASHchk);
      END_STATE();
    case 1366:
      ACCEPT_TOKEN(anon_sym_tcp_DASHcheck);
      END_STATE();
    case 1367:
      ACCEPT_TOKEN(anon_sym_tcp_DASHsmart_DASHaccept);
      END_STATE();
    case 1368:
      ACCEPT_TOKEN(anon_sym_tcp_DASHsmart_DASHconnect);
      END_STATE();
    case 1369:
      ACCEPT_TOKEN(anon_sym_tcpka);
      END_STATE();
    case 1370:
      ACCEPT_TOKEN(anon_sym_transparent);
      END_STATE();
    case 1371:
      ACCEPT_TOKEN(anon_sym_check);
      END_STATE();
    case 1372:
      ACCEPT_TOKEN(anon_sym_client);
      END_STATE();
    case 1373:
      ACCEPT_TOKEN(anon_sym_connect);
      END_STATE();
    case 1374:
      ACCEPT_TOKEN(anon_sym_http_DASHkeep_DASHalive);
      END_STATE();
    case 1375:
      ACCEPT_TOKEN(anon_sym_queue);
      END_STATE();
    case 1376:
      ACCEPT_TOKEN(anon_sym_tarpit);
      END_STATE();
    case 1377:
      ACCEPT_TOKEN(anon_sym_tunnel);
      END_STATE();
    case 1378:
      ACCEPT_TOKEN(anon_sym_enable);
      END_STATE();
    case 1379:
      ACCEPT_TOKEN(anon_sym_uri);
      END_STATE();
    case 1380:
      ACCEPT_TOKEN(anon_sym_realm);
      END_STATE();
    case 1381:
      ACCEPT_TOKEN(anon_sym_auth);
      END_STATE();
    case 1382:
      ACCEPT_TOKEN(anon_sym_refresh);
      END_STATE();
    case 1383:
      ACCEPT_TOKEN(anon_sym_admin);
      END_STATE();
    case 1384:
      ACCEPT_TOKEN(anon_sym_hide_DASHversion);
      END_STATE();
    case 1385:
      ACCEPT_TOKEN(anon_sym_show_DASHdesc);
      END_STATE();
    case 1386:
      ACCEPT_TOKEN(anon_sym_show_DASHlegends);
      END_STATE();
    case 1387:
      ACCEPT_TOKEN(anon_sym_show_DASHnode);
      END_STATE();
    case 1388:
      ACCEPT_TOKEN(anon_sym_socket);
      END_STATE();
    case 1389:
      ACCEPT_TOKEN(anon_sym_socket);
      if (lookahead == '-') ADVANCE(992);
      END_STATE();
    case 1390:
      ACCEPT_TOKEN(anon_sym_scope);
      END_STATE();
    case 1391:
      ACCEPT_TOKEN(anon_sym_add_DASHheader);
      END_STATE();
    case 1392:
      ACCEPT_TOKEN(anon_sym_set_DASHheader);
      END_STATE();
    case 1393:
      ACCEPT_TOKEN(anon_sym_del_DASHheader);
      END_STATE();
    case 1394:
      ACCEPT_TOKEN(anon_sym_replace_DASHheader);
      END_STATE();
    case 1395:
      ACCEPT_TOKEN(anon_sym_replace_DASHvalue);
      END_STATE();
    case 1396:
      ACCEPT_TOKEN(anon_sym_deny);
      END_STATE();
    case 1397:
      ACCEPT_TOKEN(anon_sym_allow);
      END_STATE();
    case 1398:
      ACCEPT_TOKEN(anon_sym_set_DASHlog_DASHlevel);
      END_STATE();
    case 1399:
      ACCEPT_TOKEN(anon_sym_set_DASHnice);
      END_STATE();
    case 1400:
      ACCEPT_TOKEN(anon_sym_set_DASHtos);
      END_STATE();
    case 1401:
      ACCEPT_TOKEN(anon_sym_set_DASHmark);
      END_STATE();
    case 1402:
      ACCEPT_TOKEN(anon_sym_add_DASHacl);
      END_STATE();
    case 1403:
      ACCEPT_TOKEN(anon_sym_del_DASHacl);
      END_STATE();
    case 1404:
      ACCEPT_TOKEN(anon_sym_set_DASHmap);
      END_STATE();
    case 1405:
      ACCEPT_TOKEN(anon_sym_del_DASHmap);
      END_STATE();
    case 1406:
      ACCEPT_TOKEN(anon_sym_disable_DASHon_DASH404);
      END_STATE();
    case 1407:
      ACCEPT_TOKEN(anon_sym_expect);
      END_STATE();
    case 1408:
      ACCEPT_TOKEN(anon_sym_send_DASHstate);
      END_STATE();
    case 1409:
      ACCEPT_TOKEN(anon_sym_connection);
      END_STATE();
    case 1410:
      ACCEPT_TOKEN(anon_sym_content);
      END_STATE();
    case 1411:
      ACCEPT_TOKEN(anon_sym_inspect_DASHdelay);
      END_STATE();
    case 1412:
      ACCEPT_TOKEN(anon_sym_match);
      END_STATE();
    case 1413:
      ACCEPT_TOKEN(anon_sym_on);
      END_STATE();
    case 1414:
      ACCEPT_TOKEN(anon_sym_store_DASHrequest);
      END_STATE();
    case 1415:
      ACCEPT_TOKEN(anon_sym_store_DASHresponse);
      END_STATE();
    case 1416:
      ACCEPT_TOKEN(anon_sym_request);
      END_STATE();
    case 1417:
      ACCEPT_TOKEN(anon_sym_header);
      END_STATE();
    case 1418:
      ACCEPT_TOKEN(anon_sym_response);
      END_STATE();
    case 1419:
      ACCEPT_TOKEN(sym_string);
      END_STATE();
    case 1420:
      ACCEPT_TOKEN(sym_ip_address);
      END_STATE();
    case 1421:
      ACCEPT_TOKEN(sym_ip_address);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(1420);
      END_STATE();
    case 1422:
      ACCEPT_TOKEN(sym_ip_address);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(1421);
      END_STATE();
    case 1423:
      ACCEPT_TOKEN(sym_ip_address);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(1422);
      END_STATE();
    case 1424:
      ACCEPT_TOKEN(sym_ip_address);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(1423);
      END_STATE();
    case 1425:
      ACCEPT_TOKEN(sym_wildcard_bind);
      END_STATE();
    case 1426:
      ACCEPT_TOKEN(sym_wildcard_bind);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(1425);
      END_STATE();
    case 1427:
      ACCEPT_TOKEN(sym_wildcard_bind);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(1426);
      END_STATE();
    case 1428:
      ACCEPT_TOKEN(sym_wildcard_bind);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(1427);
      END_STATE();
    case 1429:
      ACCEPT_TOKEN(sym_wildcard_bind);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(1428);
      END_STATE();
    case 1430:
      ACCEPT_TOKEN(sym_number);
      if (lookahead == '.') ADVANCE(73);
      if (lookahead == '5') ADVANCE(1431);
      if (lookahead == 'd' ||
          lookahead == 'h' ||
          lookahead == 's') ADVANCE(1436);
      if (lookahead == 'm') ADVANCE(1437);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(1432);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(1433);
      END_STATE();
    case 1431:
      ACCEPT_TOKEN(sym_number);
      if (lookahead == '.') ADVANCE(73);
      if (lookahead == 'd' ||
          lookahead == 'h' ||
          lookahead == 's') ADVANCE(1436);
      if (lookahead == 'm') ADVANCE(1437);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(1435);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(1432);
      END_STATE();
    case 1432:
      ACCEPT_TOKEN(sym_number);
      if (lookahead == '.') ADVANCE(73);
      if (lookahead == 'd' ||
          lookahead == 'h' ||
          lookahead == 's') ADVANCE(1436);
      if (lookahead == 'm') ADVANCE(1437);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(1435);
      END_STATE();
    case 1433:
      ACCEPT_TOKEN(sym_number);
      if (lookahead == '.') ADVANCE(73);
      if (lookahead == 'd' ||
          lookahead == 'h' ||
          lookahead == 's') ADVANCE(1436);
      if (lookahead == 'm') ADVANCE(1437);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(1432);
      END_STATE();
    case 1434:
      ACCEPT_TOKEN(sym_number);
      if (lookahead == '.') ADVANCE(73);
      if (lookahead == 'd' ||
          lookahead == 'h' ||
          lookahead == 's') ADVANCE(1436);
      if (lookahead == 'm') ADVANCE(1437);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(1433);
      END_STATE();
    case 1435:
      ACCEPT_TOKEN(sym_number);
      if (lookahead == 'd' ||
          lookahead == 'h' ||
          lookahead == 's') ADVANCE(1436);
      if (lookahead == 'm') ADVANCE(1437);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(1435);
      END_STATE();
    case 1436:
      ACCEPT_TOKEN(sym_time_value);
      END_STATE();
    case 1437:
      ACCEPT_TOKEN(sym_time_value);
      if (lookahead == 's') ADVANCE(1436);
      END_STATE();
    case 1438:
      ACCEPT_TOKEN(sym_parameter);
      END_STATE();
    case 1439:
      ACCEPT_TOKEN(anon_sym_or);
      END_STATE();
    case 1440:
      ACCEPT_TOKEN(anon_sym_or);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1441:
      ACCEPT_TOKEN(anon_sym_PIPE_PIPE);
      END_STATE();
    case 1442:
      ACCEPT_TOKEN(anon_sym_BANG);
      END_STATE();
    case 1443:
      ACCEPT_TOKEN(anon_sym_if);
      END_STATE();
    case 1444:
      ACCEPT_TOKEN(anon_sym_if);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1445:
      ACCEPT_TOKEN(anon_sym_unless);
      END_STATE();
    case 1446:
      ACCEPT_TOKEN(anon_sym_unless);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1447:
      ACCEPT_TOKEN(anon_sym_rewrite);
      END_STATE();
    case 1448:
      ACCEPT_TOKEN(anon_sym_rewrite);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1449:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == '-') ADVANCE(1502);
      if (lookahead == 'p') ADVANCE(1865);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1450:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == '-') ADVANCE(1514);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1451:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == '-') ADVANCE(1625);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1452:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == '-') ADVANCE(1676);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1453:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == '-') ADVANCE(1689);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1454:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == '-') ADVANCE(1675);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1455:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == '-') ADVANCE(1641);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1456:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == '-') ADVANCE(1846);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1457:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == '-') ADVANCE(1758);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1458:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == '-') ADVANCE(1793);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1459:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == '-') ADVANCE(1509);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1460:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == '-') ADVANCE(1840);
      if (lookahead == '_') ADVANCE(1504);
      if (lookahead == 'r') ADVANCE(1172);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1461:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == '-') ADVANCE(1842);
      if (lookahead == '_') ADVANCE(1510);
      if (lookahead == 's') ADVANCE(1145);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1462:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == '-') ADVANCE(1769);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1463:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == '_') ADVANCE(1760);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1464:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == '_') ADVANCE(1825);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1465:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == '_') ADVANCE(1795);
      if (lookahead == 'r') ADVANCE(1817);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1466:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1512);
      if (lookahead == 'i') ADVANCE(1696);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1467:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1449);
      if (lookahead == 'h') ADVANCE(1784);
      if (lookahead == 'o') ADVANCE(1686);
      if (lookahead == 'p') ADVANCE(1880);
      if (lookahead == 'r') ADVANCE(1862);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1468:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1897);
      if (lookahead == 'o') ADVANCE(1544);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1469:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1687);
      if (lookahead == 'b') ADVANCE(1762);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('c' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1470:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1541);
      if (lookahead == 'd') ADVANCE(1553);
      if (lookahead == 'i') ADVANCE(1482);
      if (lookahead == 'p') ADVANCE(1494);
      if (lookahead == 'r') ADVANCE(1581);
      if (lookahead == 's') ADVANCE(1594);
      if (lookahead == 't') ADVANCE(1487);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1471:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1571);
      if (lookahead == 'e') ADVANCE(1622);
      if (lookahead == 'i') ADVANCE(1810);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1472:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1811);
      if (lookahead == 't') ADVANCE(1872);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1473:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1545);
      if (lookahead == 'd') ADVANCE(1572);
      if (lookahead == 'i') ADVANCE(1547);
      if (lookahead == 'r') ADVANCE(1584);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1474:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1501);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1475:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1452);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1476:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1714);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1477:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1866);
      if (lookahead == 'e') ADVANCE(1542);
      if (lookahead == 's') ADVANCE(1747);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1478:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1866);
      if (lookahead == 'e') ADVANCE(1543);
      if (lookahead == 's') ADVANCE(1747);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1479:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1881);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1480:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1668);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1481:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1867);
      if (lookahead == 'i') ADVANCE(1516);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1482:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1685);
      if (lookahead == 'd') ADVANCE(1575);
      if (lookahead == 'p') ADVANCE(1497);
      if (lookahead == 'r') ADVANCE(1595);
      if (lookahead == 's') ADVANCE(1608);
      if (lookahead == 't') ADVANCE(1500);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1483:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1751);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1484:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1518);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1485:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1868);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1486:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1538);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1487:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1790);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1488:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1548);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1489:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1853);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1490:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1861);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1491:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1507);
      if (lookahead == 'p') ADVANCE(1485);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1492:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1521);
      if (lookahead == 'o') ADVANCE(1882);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1493:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1835);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1494:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1823);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1495:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1508);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1496:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1836);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1497:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1826);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1498:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1877);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1499:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1528);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1500:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'a') ADVANCE(1804);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('b' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1501:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'b') ADVANCE(1680);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1502:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'b') ADVANCE(1493);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1503:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'b') ADVANCE(1480);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1504:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'b') ADVANCE(1484);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1505:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'b') ADVANCE(1563);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1506:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'b') ADVANCE(1566);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1507:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'b') ADVANCE(1681);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1508:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'b') ADVANCE(1683);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1509:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'b') ADVANCE(1496);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1510:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'b') ADVANCE(1499);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1511:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'c') ADVANCE(1666);
      if (lookahead == 'g') ADVANCE(1628);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1512:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'c') ADVANCE(1660);
      if (lookahead == 'l') ADVANCE(1476);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1513:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'c') ADVANCE(1216);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1514:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'c') ADVANCE(1632);
      if (lookahead == 'r') ADVANCE(1618);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1515:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'c') ADVANCE(1756);
      if (lookahead == 'i') ADVANCE(1688);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1516:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'c') ADVANCE(1661);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1517:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'c') ADVANCE(1630);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1518:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'c') ADVANCE(1664);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1519:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'c') ADVANCE(1662);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1520:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'c') ADVANCE(1786);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1521:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'c') ADVANCE(1552);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1522:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'c') ADVANCE(1850);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1523:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'c') ADVANCE(1555);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1524:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'c') ADVANCE(1557);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1525:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'c') ADVANCE(1588);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1526:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'c') ADVANCE(1726);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1527:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'c') ADVANCE(1617);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1528:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'c') ADVANCE(1665);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1529:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'd') ADVANCE(1198);
      if (lookahead == 'f') ADVANCE(1444);
      if (lookahead == 'g') ADVANCE(1704);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1530:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'd') ADVANCE(1198);
      if (lookahead == 'g') ADVANCE(1704);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1531:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'd') ADVANCE(1162);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1532:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'd') ADVANCE(1252);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1533:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'd') ADVANCE(1282);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1534:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'd') ADVANCE(1149);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1535:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'd') ADVANCE(1202);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1536:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'd') ADVANCE(1200);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1537:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'd') ADVANCE(1147);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1538:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'd') ADVANCE(1220);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1539:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'd') ADVANCE(1190);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1540:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'd') ADVANCE(1188);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1541:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'd') ADVANCE(1532);
      if (lookahead == 'l') ADVANCE(1678);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1542:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'd') ADVANCE(1650);
      if (lookahead == 'q') ADVANCE(1470);
      if (lookahead == 's') ADVANCE(1722);
      if (lookahead == 't') ADVANCE(1799);
      if (lookahead == 'w') ADVANCE(1796);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1543:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'd') ADVANCE(1650);
      if (lookahead == 'q') ADVANCE(1470);
      if (lookahead == 's') ADVANCE(1722);
      if (lookahead == 't') ADVANCE(1799);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1544:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'd') ADVANCE(1551);
      if (lookahead == 'n') ADVANCE(1639);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1545:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'd') ADVANCE(1533);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1546:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'd') ADVANCE(1451);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1547:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'd') ADVANCE(1577);
      if (lookahead == 'r') ADVANCE(1596);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1548:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'd') ADVANCE(1603);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1549:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1578);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1550:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1460);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1551:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1169);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1552:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1226);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1553:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1669);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1554:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1184);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1555:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1196);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1556:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1771);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1557:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1167);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1558:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1212);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1559:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1316);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1560:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1465);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1561:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1448);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1562:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1214);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1563:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1278);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1564:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1186);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1565:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1228);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1566:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1270);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1567:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1314);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1568:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1310);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1569:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1304);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1570:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1248);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1571:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1690);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1572:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1670);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1573:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1629);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1574:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1774);
      if (lookahead == 'o') ADVANCE(1887);
      if (lookahead == 't') ADVANCE(1481);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1575:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1671);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1576:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1896);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1577:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1672);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1578:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1775);
      if (lookahead == 'r') ADVANCE(1821);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1579:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1830);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1580:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1698);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1581:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1749);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1582:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1535);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1583:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1822);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1584:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1750);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1585:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1536);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1586:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1454);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1587:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1522);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1588:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1457);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1589:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1727);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1590:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1455);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1591:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1519);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1592:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1815);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1593:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1776);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1594:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1864);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1595:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1752);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1596:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1753);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1597:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1807);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1598:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1488);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1599:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1778);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1600:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1820);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1601:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1779);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1602:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1780);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1603:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1781);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1604:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1856);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1605:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1879);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1606:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1705);
      if (lookahead == 'l') ADVANCE(1723);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1607:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1797);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1608:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1873);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1609:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1706);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1610:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1800);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1611:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1824);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1612:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1708);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1613:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1803);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1614:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1831);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1615:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1710);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1616:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1832);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1617:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1828);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1618:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1772);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1619:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1808);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1620:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'e') ADVANCE(1462);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1621:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'f') ADVANCE(1444);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1622:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'f') ADVANCE(1479);
      if (lookahead == 's') ADVANCE(1520);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1623:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'f') ADVANCE(1647);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1624:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'f') ADVANCE(1736);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1625:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'f') ADVANCE(1746);
      if (lookahead == 'h') ADVANCE(1598);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1626:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'g') ADVANCE(1179);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1627:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'g') ADVANCE(1206);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1628:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'g') ADVANCE(1787);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1629:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'g') ADVANCE(1498);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1630:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'h') ADVANCE(1204);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1631:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'h') ADVANCE(1456);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1632:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'h') ADVANCE(1591);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1633:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1770);
      if (lookahead == 'l') ADVANCE(1583);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1634:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1770);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1635:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1224);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1636:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1903);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1637:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1839);
      if (lookahead == 'o') ADVANCE(1626);
      if (lookahead == 'u') ADVANCE(1475);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1638:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1693);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1639:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1874);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1640:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1768);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1641:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1546);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1642:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1554);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1643:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1852);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1644:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1854);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1645:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1855);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1646:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1827);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1647:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1682);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1648:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1829);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1649:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1729);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1650:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1792);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1651:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1871);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1652:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1592);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1653:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1733);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1654:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1600);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1655:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1833);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1656:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1735);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1657:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1834);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1658:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1737);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1659:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'i') ADVANCE(1740);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1660:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'k') ADVANCE(1606);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1661:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'k') ADVANCE(1311);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1662:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'k') ADVANCE(1306);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1663:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'k') ADVANCE(1642);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1664:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'k') ADVANCE(1612);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1665:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'k') ADVANCE(1615);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1666:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'l') ADVANCE(1161);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1667:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'l') ADVANCE(1888);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1668:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'l') ADVANCE(1143);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1669:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'l') ADVANCE(1256);
      if (lookahead == 'n') ADVANCE(1898);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1670:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'l') ADVANCE(1284);
      if (lookahead == 'n') ADVANCE(1899);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1671:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'l') ADVANCE(1262);
      if (lookahead == 'n') ADVANCE(1900);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1672:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'l') ADVANCE(1288);
      if (lookahead == 'n') ADVANCE(1901);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1673:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'l') ADVANCE(1742);
      if (lookahead == 'r') ADVANCE(1492);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1674:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'l') ADVANCE(1464);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1675:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'l') ADVANCE(1638);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1676:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'l') ADVANCE(1739);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1677:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'l') ADVANCE(1847);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1678:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'l') ADVANCE(1718);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1679:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'l') ADVANCE(1720);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1680:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'l') ADVANCE(1582);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1681:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'l') ADVANCE(1585);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1682:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'l') ADVANCE(1564);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1683:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'l') ADVANCE(1567);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1684:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'l') ADVANCE(1583);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1685:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'l') ADVANCE(1679);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1686:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'm') ADVANCE(1761);
      if (lookahead == 'o') ADVANCE(1663);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1687:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'm') ADVANCE(1579);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1688:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'm') ADVANCE(1589);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1689:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'm') ADVANCE(1483);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1690:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'm') ADVANCE(1724);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1691:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'm') ADVANCE(1489);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1692:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'm') ADVANCE(1490);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1693:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'm') ADVANCE(1644);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1694:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'n') ADVANCE(1474);
      if (lookahead == 'r') ADVANCE(1785);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1695:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'n') ADVANCE(1633);
      if (lookahead == 's') ADVANCE(1550);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1696:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'n') ADVANCE(1531);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1697:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'n') ADVANCE(1177);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1698:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'n') ADVANCE(1151);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1699:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'n') ADVANCE(1296);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1700:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'n') ADVANCE(1171);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1701:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'n') ADVANCE(1463);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1702:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'n') ADVANCE(1192);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1703:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'n') ADVANCE(1208);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1704:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'n') ADVANCE(1743);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1705:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'n') ADVANCE(1534);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1706:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'n') ADVANCE(1537);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1707:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'n') ADVANCE(1700);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1708:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'n') ADVANCE(1539);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1709:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'n') ADVANCE(1634);
      if (lookahead == 's') ADVANCE(1550);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1710:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'n') ADVANCE(1540);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1711:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'n') ADVANCE(1818);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1712:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'n') ADVANCE(1604);
      if (lookahead == 'u') ADVANCE(1789);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1713:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'n') ADVANCE(1870);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1714:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'n') ADVANCE(1524);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1715:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'n') ADVANCE(1837);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1716:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'n') ADVANCE(1684);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1717:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'n') ADVANCE(1838);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1718:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1894);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1719:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1782);
      if (lookahead == 'r') ADVANCE(1721);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1720:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1895);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1721:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1713);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1722:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1667);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1723:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1627);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1724:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1697);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1725:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1513);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1726:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1707);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1727:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1883);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1728:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1730);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1729:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1699);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1730:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1845);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1731:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1674);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1732:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1783);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1733:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1701);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1734:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1715);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1735:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1711);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1736:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1798);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1737:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1702);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1738:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1777);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1739:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1486);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1740:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1703);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1741:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1731);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1742:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1503);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1743:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1809);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1744:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1527);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1745:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1717);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1746:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'o') ADVANCE(1805);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1747:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'p') ADVANCE(1473);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1748:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'p') ADVANCE(1175);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1749:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'p') ADVANCE(1276);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1750:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'p') ADVANCE(1294);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1751:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'p') ADVANCE(1218);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1752:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'p') ADVANCE(1268);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1753:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'p') ADVANCE(1292);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1754:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'p') ADVANCE(1863);
      if (lookahead == 'r') ADVANCE(1440);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1755:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'p') ADVANCE(1863);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1756:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'p') ADVANCE(1458);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1757:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'p') ADVANCE(1450);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1758:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'p') ADVANCE(1597);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1759:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'p') ADVANCE(1565);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1760:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'p') ADVANCE(1741);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1761:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'p') ADVANCE(1802);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1762:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'p') ADVANCE(1788);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1763:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'p') ADVANCE(1643);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1764:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'p') ADVANCE(1791);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1765:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'p') ADVANCE(1645);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1766:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'p') ADVANCE(1734);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1767:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'p') ADVANCE(1745);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1768:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'p') ADVANCE(1878);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1769:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'p') ADVANCE(1619);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1770:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'q') ADVANCE(1885);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1771:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'q') ADVANCE(1884);
      if (lookahead == 's') ADVANCE(1766);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1772:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'q') ADVANCE(1889);
      if (lookahead == 's') ADVANCE(1767);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1773:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1440);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1774:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1890);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1775:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1246);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1776:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1165);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1777:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1320);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1778:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1244);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1779:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1318);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1780:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1236);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1781:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1242);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1782:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1525);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1783:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1623);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1784:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1728);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1785:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1732);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1786:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1640);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1787:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1573);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1788:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1725);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1789:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1635);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1790:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1763);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1791:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1744);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1792:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1587);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1793:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1556);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1794:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1559);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1795:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1605);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1796:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1651);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1797:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1891);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1798:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1691);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1799:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1652);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1800:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1892);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1801:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1523);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1802:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1611);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1803:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1893);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1804:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1765);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1805:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1692);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1806:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1654);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1807:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1841);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1808:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1844);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1809:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'r') ADVANCE(1620);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1810:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1491);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1811:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1631);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1812:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1300);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1813:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1446);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1814:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1274);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1815:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1182);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1816:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1266);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1817:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1155);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1818:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1159);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1819:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1234);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1820:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1250);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1821:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1646);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1822:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1813);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1823:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1814);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1824:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1843);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1825:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1636);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1826:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1816);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1827:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1848);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1828:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1819);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1829:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1851);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1830:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1607);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1831:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1857);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1832:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1858);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1833:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1859);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1834:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1860);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1835:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1558);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1836:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1562);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1837:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1568);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1838:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1569);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1839:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1869);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1840:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1610);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1841:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1655);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1842:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1613);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1843:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1658);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1844:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 's') ADVANCE(1657);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1845:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1210);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1846:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1902);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1847:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1461);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1848:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1326);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1849:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1298);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1850:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1194);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1851:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1157);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1852:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1280);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1853:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1238);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1854:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1323);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1855:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1272);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1856:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1222);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1857:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1308);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1858:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1302);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1859:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1230);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1860:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1232);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1861:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1240);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1862:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1459);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1863:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1649);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1864:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1505);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1865:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1886);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1866:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1586);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1867:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1812);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1868:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1517);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1869:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1580);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1870:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1609);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1871:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1561);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1872:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1757);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1873:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1506);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1874:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1738);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1875:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1495);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1876:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1653);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1877:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1656);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1878:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1659);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1879:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 't') ADVANCE(1806);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1880:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'u') ADVANCE(1453);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1881:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'u') ADVANCE(1677);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1882:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'u') ADVANCE(1748);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1883:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'u') ADVANCE(1849);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1884:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'u') ADVANCE(1614);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1885:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'u') ADVANCE(1590);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1886:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'u') ADVANCE(1794);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1887:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'u') ADVANCE(1801);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1888:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'u') ADVANCE(1876);
      if (lookahead == 'v') ADVANCE(1560);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1889:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'u') ADVANCE(1616);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1890:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'v') ADVANCE(1593);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1891:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'v') ADVANCE(1599);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1892:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'v') ADVANCE(1601);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1893:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'v') ADVANCE(1602);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1894:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'w') ADVANCE(1254);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1895:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'w') ADVANCE(1260);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1896:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'w') ADVANCE(1796);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1897:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'x') ADVANCE(1526);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1898:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'y') ADVANCE(1258);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1899:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'y') ADVANCE(1286);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1900:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'y') ADVANCE(1264);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1901:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'y') ADVANCE(1290);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1902:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'y') ADVANCE(1759);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1903:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == 'z') ADVANCE(1570);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'y')) ADVANCE(1904);
      END_STATE();
    case 1904:
      ACCEPT_TOKEN(sym_identifier);
      if (lookahead == '-' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1904);
      END_STATE();
    case 1905:
      ACCEPT_TOKEN(sym_path);
      if (('!' <= lookahead && lookahead <= '+') ||
          ('-' <= lookahead && lookahead <= '~')) ADVANCE(1905);
      END_STATE();
    default:
      return false;
  }
}

static const TSLexMode ts_lex_modes[STATE_COUNT] = {
  [0] = {.lex_state = 0},
  [1] = {.lex_state = 1138},
  [2] = {.lex_state = 1137},
  [3] = {.lex_state = 1137},
  [4] = {.lex_state = 1137},
  [5] = {.lex_state = 1137},
  [6] = {.lex_state = 1137},
  [7] = {.lex_state = 1137},
  [8] = {.lex_state = 1137},
  [9] = {.lex_state = 1137},
  [10] = {.lex_state = 1137},
  [11] = {.lex_state = 1137},
  [12] = {.lex_state = 1137},
  [13] = {.lex_state = 1137},
  [14] = {.lex_state = 1137},
  [15] = {.lex_state = 1137},
  [16] = {.lex_state = 1137},
  [17] = {.lex_state = 1137},
  [18] = {.lex_state = 1137},
  [19] = {.lex_state = 1137},
  [20] = {.lex_state = 1138},
  [21] = {.lex_state = 1138},
  [22] = {.lex_state = 1139},
  [23] = {.lex_state = 1138},
  [24] = {.lex_state = 1138},
  [25] = {.lex_state = 1138},
  [26] = {.lex_state = 1138},
  [27] = {.lex_state = 1139},
  [28] = {.lex_state = 1138},
  [29] = {.lex_state = 3},
  [30] = {.lex_state = 1},
  [31] = {.lex_state = 1},
  [32] = {.lex_state = 1},
  [33] = {.lex_state = 0},
  [34] = {.lex_state = 4},
  [35] = {.lex_state = 0},
  [36] = {.lex_state = 0},
  [37] = {.lex_state = 0},
  [38] = {.lex_state = 1138},
  [39] = {.lex_state = 0},
  [40] = {.lex_state = 0},
  [41] = {.lex_state = 0},
  [42] = {.lex_state = 0},
  [43] = {.lex_state = 0},
  [44] = {.lex_state = 0},
  [45] = {.lex_state = 0},
};

static const uint16_t ts_parse_table[LARGE_STATE_COUNT][SYMBOL_COUNT] = {
  [0] = {
    [ts_builtin_sym_end] = ACTIONS(1),
    [sym_comment] = ACTIONS(3),
    [anon_sym_global] = ACTIONS(1),
    [anon_sym_defaults] = ACTIONS(1),
    [anon_sym_frontend] = ACTIONS(1),
    [anon_sym_backend] = ACTIONS(1),
    [anon_sym_listen] = ACTIONS(1),
    [anon_sym_peers] = ACTIONS(1),
    [anon_sym_resolvers] = ACTIONS(1),
    [anon_sym_userlist] = ACTIONS(1),
    [anon_sym_aggregations] = ACTIONS(1),
    [anon_sym_acl] = ACTIONS(1),
    [anon_sym_bind] = ACTIONS(1),
    [anon_sym_server] = ACTIONS(1),
    [anon_sym_balance] = ACTIONS(1),
    [anon_sym_mode] = ACTIONS(1),
    [anon_sym_maxconn] = ACTIONS(1),
    [anon_sym_user] = ACTIONS(1),
    [anon_sym_group] = ACTIONS(1),
    [anon_sym_daemon] = ACTIONS(1),
    [anon_sym_log] = ACTIONS(1),
    [anon_sym_retries] = ACTIONS(1),
    [anon_sym_cookie] = ACTIONS(1),
    [anon_sym_errorfile] = ACTIONS(1),
    [anon_sym_default_backend] = ACTIONS(1),
    [anon_sym_use_backend] = ACTIONS(1),
    [anon_sym_compression] = ACTIONS(1),
    [anon_sym_redirect] = ACTIONS(1),
    [anon_sym_source] = ACTIONS(1),
    [anon_sym_id] = ACTIONS(1),
    [anon_sym_disabled] = ACTIONS(1),
    [anon_sym_dispatch] = ACTIONS(1),
    [anon_sym_backlog] = ACTIONS(1),
    [anon_sym_description] = ACTIONS(1),
    [anon_sym_chroot] = ACTIONS(1),
    [anon_sym_ca_DASHbase] = ACTIONS(1),
    [anon_sym_crt_DASHbase] = ACTIONS(1),
    [anon_sym_nbproc] = ACTIONS(1),
    [anon_sym_cpu_DASHmap] = ACTIONS(1),
    [anon_sym_lua_DASHload] = ACTIONS(1),
    [anon_sym_monitor_DASHnet] = ACTIONS(1),
    [anon_sym_monitor_DASHuri] = ACTIONS(1),
    [anon_sym_grace] = ACTIONS(1),
    [anon_sym_hash_DASHtype] = ACTIONS(1),
    [anon_sym_force_DASHpersist] = ACTIONS(1),
    [anon_sym_ignore_DASHpersist] = ACTIONS(1),
    [anon_sym_bind_DASHprocess] = ACTIONS(1),
    [anon_sym_default_DASHserver] = ACTIONS(1),
    [anon_sym_log_DASHformat] = ACTIONS(1),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(1),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(1),
    [anon_sym_nameserver] = ACTIONS(1),
    [anon_sym_peer] = ACTIONS(1),
    [anon_sym_resolution_pool_size] = ACTIONS(1),
    [anon_sym_resolve_retries] = ACTIONS(1),
    [anon_sym_reqadd] = ACTIONS(1),
    [anon_sym_reqallow] = ACTIONS(1),
    [anon_sym_reqdel] = ACTIONS(1),
    [anon_sym_reqdeny] = ACTIONS(1),
    [anon_sym_reqiallow] = ACTIONS(1),
    [anon_sym_reqidel] = ACTIONS(1),
    [anon_sym_reqideny] = ACTIONS(1),
    [anon_sym_reqipass] = ACTIONS(1),
    [anon_sym_reqirep] = ACTIONS(1),
    [anon_sym_reqisetbe] = ACTIONS(1),
    [anon_sym_reqitarpit] = ACTIONS(1),
    [anon_sym_reqpass] = ACTIONS(1),
    [anon_sym_reqrep] = ACTIONS(1),
    [anon_sym_reqsetbe] = ACTIONS(1),
    [anon_sym_reqtarpit] = ACTIONS(1),
    [anon_sym_rspadd] = ACTIONS(1),
    [anon_sym_rspdel] = ACTIONS(1),
    [anon_sym_rspdeny] = ACTIONS(1),
    [anon_sym_rspidel] = ACTIONS(1),
    [anon_sym_rspideny] = ACTIONS(1),
    [anon_sym_rspirep] = ACTIONS(1),
    [anon_sym_rsprep] = ACTIONS(1),
    [anon_sym_option] = ACTIONS(1),
    [anon_sym_timeout] = ACTIONS(1),
    [anon_sym_stats] = ACTIONS(1),
    [anon_sym_http_DASHrequest] = ACTIONS(1),
    [anon_sym_http_DASHresponse] = ACTIONS(1),
    [anon_sym_http_DASHcheck] = ACTIONS(1),
    [anon_sym_tcp_DASHrequest] = ACTIONS(1),
    [anon_sym_tcp_DASHresponse] = ACTIONS(1),
    [anon_sym_stick] = ACTIONS(1),
    [anon_sym_stick_DASHtable] = ACTIONS(1),
    [anon_sym_capture] = ACTIONS(1),
    [anon_sym_use_DASHserver] = ACTIONS(1),
    [anon_sym_monitor] = ACTIONS(1),
    [anon_sym_fail] = ACTIONS(1),
    [anon_sym_rate_DASHlimit] = ACTIONS(1),
    [anon_sym_sessions] = ACTIONS(1),
    [anon_sym_persist] = ACTIONS(1),
    [anon_sym_rdp_DASHcookie] = ACTIONS(1),
    [anon_sym_httplog] = ACTIONS(1),
    [anon_sym_tcplog] = ACTIONS(1),
    [anon_sym_httpchk] = ACTIONS(1),
    [anon_sym_forwardfor] = ACTIONS(1),
    [anon_sym_redispatch] = ACTIONS(1),
    [anon_sym_abortonclose] = ACTIONS(1),
    [anon_sym_accept_DASHinvalid_DASHhttp_DASHrequest] = ACTIONS(1),
    [anon_sym_accept_DASHinvalid_DASHhttp_DASHresponse] = ACTIONS(1),
    [anon_sym_allbackups] = ACTIONS(1),
    [anon_sym_clitcpka] = ACTIONS(1),
    [anon_sym_contstats] = ACTIONS(1),
    [anon_sym_dontlog_DASHnormal] = ACTIONS(1),
    [anon_sym_dontlognull] = ACTIONS(1),
    [anon_sym_forceclose] = ACTIONS(1),
    [anon_sym_http_DASHno_DASHdelay] = ACTIONS(1),
    [anon_sym_http_DASHpretend_DASHkeepalive] = ACTIONS(1),
    [anon_sym_http_DASHserver_DASHclose] = ACTIONS(1),
    [anon_sym_http_DASHuse_DASHproxy_DASHheader] = ACTIONS(1),
    [anon_sym_httpclose] = ACTIONS(1),
    [anon_sym_http_proxy] = ACTIONS(1),
    [anon_sym_independent_DASHstreams] = ACTIONS(1),
    [anon_sym_ldap_DASHcheck] = ACTIONS(1),
    [anon_sym_log_DASHhealth_DASHchecks] = ACTIONS(1),
    [anon_sym_log_DASHseparate_DASHerrors] = ACTIONS(1),
    [anon_sym_mysql_DASHcheck] = ACTIONS(1),
    [anon_sym_pgsql_DASHcheck] = ACTIONS(1),
    [anon_sym_nolinger] = ACTIONS(1),
    [anon_sym_redis_DASHcheck] = ACTIONS(1),
    [anon_sym_smtpchk] = ACTIONS(1),
    [anon_sym_socket_DASHstats] = ACTIONS(1),
    [anon_sym_splice_DASHauto] = ACTIONS(1),
    [anon_sym_splice_DASHrequest] = ACTIONS(1),
    [anon_sym_splice_DASHresponse] = ACTIONS(1),
    [anon_sym_srvtcpka] = ACTIONS(1),
    [anon_sym_ssl_DASHhello_DASHchk] = ACTIONS(1),
    [anon_sym_tcp_DASHcheck] = ACTIONS(1),
    [anon_sym_tcp_DASHsmart_DASHaccept] = ACTIONS(1),
    [anon_sym_tcp_DASHsmart_DASHconnect] = ACTIONS(1),
    [anon_sym_tcpka] = ACTIONS(1),
    [anon_sym_transparent] = ACTIONS(1),
    [anon_sym_check] = ACTIONS(1),
    [anon_sym_client] = ACTIONS(1),
    [anon_sym_connect] = ACTIONS(1),
    [anon_sym_http_DASHkeep_DASHalive] = ACTIONS(1),
    [anon_sym_queue] = ACTIONS(1),
    [anon_sym_tarpit] = ACTIONS(1),
    [anon_sym_tunnel] = ACTIONS(1),
    [anon_sym_enable] = ACTIONS(1),
    [anon_sym_uri] = ACTIONS(1),
    [anon_sym_realm] = ACTIONS(1),
    [anon_sym_auth] = ACTIONS(1),
    [anon_sym_refresh] = ACTIONS(1),
    [anon_sym_admin] = ACTIONS(1),
    [anon_sym_hide_DASHversion] = ACTIONS(1),
    [anon_sym_show_DASHdesc] = ACTIONS(1),
    [anon_sym_show_DASHlegends] = ACTIONS(1),
    [anon_sym_show_DASHnode] = ACTIONS(1),
    [anon_sym_socket] = ACTIONS(1),
    [anon_sym_scope] = ACTIONS(1),
    [anon_sym_add_DASHheader] = ACTIONS(1),
    [anon_sym_set_DASHheader] = ACTIONS(1),
    [anon_sym_del_DASHheader] = ACTIONS(1),
    [anon_sym_replace_DASHheader] = ACTIONS(1),
    [anon_sym_replace_DASHvalue] = ACTIONS(1),
    [anon_sym_deny] = ACTIONS(1),
    [anon_sym_allow] = ACTIONS(1),
    [anon_sym_set_DASHlog_DASHlevel] = ACTIONS(1),
    [anon_sym_set_DASHnice] = ACTIONS(1),
    [anon_sym_set_DASHtos] = ACTIONS(1),
    [anon_sym_set_DASHmark] = ACTIONS(1),
    [anon_sym_add_DASHacl] = ACTIONS(1),
    [anon_sym_del_DASHacl] = ACTIONS(1),
    [anon_sym_set_DASHmap] = ACTIONS(1),
    [anon_sym_del_DASHmap] = ACTIONS(1),
    [anon_sym_disable_DASHon_DASH404] = ACTIONS(1),
    [anon_sym_expect] = ACTIONS(1),
    [anon_sym_send_DASHstate] = ACTIONS(1),
    [anon_sym_content] = ACTIONS(1),
    [anon_sym_inspect_DASHdelay] = ACTIONS(1),
    [anon_sym_match] = ACTIONS(1),
    [anon_sym_on] = ACTIONS(1),
    [anon_sym_store_DASHrequest] = ACTIONS(1),
    [anon_sym_store_DASHresponse] = ACTIONS(1),
    [anon_sym_request] = ACTIONS(1),
    [anon_sym_header] = ACTIONS(1),
    [anon_sym_response] = ACTIONS(1),
    [sym_string] = ACTIONS(1),
    [sym_ip_address] = ACTIONS(1),
    [sym_wildcard_bind] = ACTIONS(1),
    [sym_number] = ACTIONS(1),
    [sym_time_value] = ACTIONS(1),
    [sym_parameter] = ACTIONS(1),
    [anon_sym_or] = ACTIONS(1),
    [anon_sym_PIPE_PIPE] = ACTIONS(1),
    [anon_sym_BANG] = ACTIONS(1),
    [anon_sym_if] = ACTIONS(1),
    [anon_sym_unless] = ACTIONS(1),
    [anon_sym_rewrite] = ACTIONS(1),
    [sym_path] = ACTIONS(1),
  },
  [1] = {
    [sym_source_file] = STATE(41),
    [sym__statement] = STATE(21),
    [sym_section] = STATE(21),
    [sym_section_name] = STATE(22),
    [sym_directive] = STATE(21),
    [sym_keyword] = STATE(2),
    [sym_keyword_combination] = STATE(2),
    [aux_sym_source_file_repeat1] = STATE(21),
    [ts_builtin_sym_end] = ACTIONS(5),
    [sym_comment] = ACTIONS(7),
    [anon_sym_global] = ACTIONS(9),
    [anon_sym_defaults] = ACTIONS(9),
    [anon_sym_frontend] = ACTIONS(9),
    [anon_sym_backend] = ACTIONS(9),
    [anon_sym_listen] = ACTIONS(9),
    [anon_sym_peers] = ACTIONS(9),
    [anon_sym_resolvers] = ACTIONS(9),
    [anon_sym_userlist] = ACTIONS(9),
    [anon_sym_aggregations] = ACTIONS(9),
    [anon_sym_acl] = ACTIONS(11),
    [anon_sym_bind] = ACTIONS(13),
    [anon_sym_server] = ACTIONS(11),
    [anon_sym_balance] = ACTIONS(11),
    [anon_sym_mode] = ACTIONS(11),
    [anon_sym_maxconn] = ACTIONS(11),
    [anon_sym_user] = ACTIONS(13),
    [anon_sym_group] = ACTIONS(11),
    [anon_sym_daemon] = ACTIONS(11),
    [anon_sym_log] = ACTIONS(13),
    [anon_sym_retries] = ACTIONS(11),
    [anon_sym_cookie] = ACTIONS(11),
    [anon_sym_errorfile] = ACTIONS(11),
    [anon_sym_default_backend] = ACTIONS(11),
    [anon_sym_use_backend] = ACTIONS(11),
    [anon_sym_compression] = ACTIONS(11),
    [anon_sym_redirect] = ACTIONS(11),
    [anon_sym_source] = ACTIONS(11),
    [anon_sym_id] = ACTIONS(11),
    [anon_sym_disabled] = ACTIONS(11),
    [anon_sym_enabled] = ACTIONS(11),
    [anon_sym_dispatch] = ACTIONS(11),
    [anon_sym_backlog] = ACTIONS(11),
    [anon_sym_description] = ACTIONS(11),
    [anon_sym_chroot] = ACTIONS(11),
    [anon_sym_ca_DASHbase] = ACTIONS(11),
    [anon_sym_crt_DASHbase] = ACTIONS(11),
    [anon_sym_nbproc] = ACTIONS(11),
    [anon_sym_cpu_DASHmap] = ACTIONS(11),
    [anon_sym_lua_DASHload] = ACTIONS(11),
    [anon_sym_monitor_DASHnet] = ACTIONS(11),
    [anon_sym_monitor_DASHuri] = ACTIONS(11),
    [anon_sym_grace] = ACTIONS(11),
    [anon_sym_hash_DASHtype] = ACTIONS(11),
    [anon_sym_force_DASHpersist] = ACTIONS(11),
    [anon_sym_ignore_DASHpersist] = ACTIONS(11),
    [anon_sym_bind_DASHprocess] = ACTIONS(11),
    [anon_sym_default_DASHserver] = ACTIONS(11),
    [anon_sym_log_DASHformat] = ACTIONS(11),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(11),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(11),
    [anon_sym_nameserver] = ACTIONS(11),
    [anon_sym_peer] = ACTIONS(13),
    [anon_sym_resolution_pool_size] = ACTIONS(11),
    [anon_sym_resolve_retries] = ACTIONS(11),
    [anon_sym_reqadd] = ACTIONS(11),
    [anon_sym_reqallow] = ACTIONS(11),
    [anon_sym_reqdel] = ACTIONS(11),
    [anon_sym_reqdeny] = ACTIONS(11),
    [anon_sym_reqiallow] = ACTIONS(11),
    [anon_sym_reqidel] = ACTIONS(11),
    [anon_sym_reqideny] = ACTIONS(11),
    [anon_sym_reqipass] = ACTIONS(11),
    [anon_sym_reqirep] = ACTIONS(11),
    [anon_sym_reqisetbe] = ACTIONS(11),
    [anon_sym_reqitarpit] = ACTIONS(11),
    [anon_sym_reqpass] = ACTIONS(11),
    [anon_sym_reqrep] = ACTIONS(11),
    [anon_sym_reqsetbe] = ACTIONS(11),
    [anon_sym_reqtarpit] = ACTIONS(11),
    [anon_sym_rspadd] = ACTIONS(11),
    [anon_sym_rspdel] = ACTIONS(11),
    [anon_sym_rspdeny] = ACTIONS(11),
    [anon_sym_rspidel] = ACTIONS(11),
    [anon_sym_rspideny] = ACTIONS(11),
    [anon_sym_rspirep] = ACTIONS(11),
    [anon_sym_rsprep] = ACTIONS(11),
    [anon_sym_option] = ACTIONS(15),
    [anon_sym_timeout] = ACTIONS(17),
    [anon_sym_stats] = ACTIONS(19),
    [anon_sym_http_DASHrequest] = ACTIONS(21),
    [anon_sym_http_DASHresponse] = ACTIONS(21),
    [anon_sym_http_DASHcheck] = ACTIONS(23),
    [anon_sym_tcp_DASHrequest] = ACTIONS(25),
    [anon_sym_tcp_DASHresponse] = ACTIONS(27),
    [anon_sym_stick] = ACTIONS(29),
    [anon_sym_stick_DASHtable] = ACTIONS(31),
    [anon_sym_capture] = ACTIONS(33),
    [anon_sym_use_DASHserver] = ACTIONS(31),
    [anon_sym_monitor] = ACTIONS(35),
    [anon_sym_rate_DASHlimit] = ACTIONS(37),
    [anon_sym_persist] = ACTIONS(39),
  },
  [2] = {
    [sym_arguments] = STATE(28),
    [sym__argument] = STATE(3),
    [sym_operator] = STATE(3),
    [sym_control_flow] = STATE(3),
    [aux_sym_arguments_repeat1] = STATE(3),
    [ts_builtin_sym_end] = ACTIONS(41),
    [sym_comment] = ACTIONS(41),
    [anon_sym_global] = ACTIONS(43),
    [anon_sym_defaults] = ACTIONS(43),
    [anon_sym_frontend] = ACTIONS(43),
    [anon_sym_backend] = ACTIONS(43),
    [anon_sym_listen] = ACTIONS(43),
    [anon_sym_peers] = ACTIONS(43),
    [anon_sym_resolvers] = ACTIONS(43),
    [anon_sym_userlist] = ACTIONS(43),
    [anon_sym_aggregations] = ACTIONS(43),
    [anon_sym_acl] = ACTIONS(43),
    [anon_sym_bind] = ACTIONS(43),
    [anon_sym_server] = ACTIONS(43),
    [anon_sym_balance] = ACTIONS(43),
    [anon_sym_mode] = ACTIONS(43),
    [anon_sym_maxconn] = ACTIONS(43),
    [anon_sym_user] = ACTIONS(43),
    [anon_sym_group] = ACTIONS(43),
    [anon_sym_daemon] = ACTIONS(43),
    [anon_sym_log] = ACTIONS(43),
    [anon_sym_retries] = ACTIONS(43),
    [anon_sym_cookie] = ACTIONS(43),
    [anon_sym_errorfile] = ACTIONS(43),
    [anon_sym_default_backend] = ACTIONS(43),
    [anon_sym_use_backend] = ACTIONS(43),
    [anon_sym_compression] = ACTIONS(43),
    [anon_sym_redirect] = ACTIONS(43),
    [anon_sym_source] = ACTIONS(43),
    [anon_sym_id] = ACTIONS(43),
    [anon_sym_disabled] = ACTIONS(43),
    [anon_sym_enabled] = ACTIONS(43),
    [anon_sym_dispatch] = ACTIONS(43),
    [anon_sym_backlog] = ACTIONS(43),
    [anon_sym_description] = ACTIONS(43),
    [anon_sym_chroot] = ACTIONS(43),
    [anon_sym_ca_DASHbase] = ACTIONS(43),
    [anon_sym_crt_DASHbase] = ACTIONS(43),
    [anon_sym_nbproc] = ACTIONS(43),
    [anon_sym_cpu_DASHmap] = ACTIONS(43),
    [anon_sym_lua_DASHload] = ACTIONS(43),
    [anon_sym_monitor_DASHnet] = ACTIONS(43),
    [anon_sym_monitor_DASHuri] = ACTIONS(43),
    [anon_sym_grace] = ACTIONS(43),
    [anon_sym_hash_DASHtype] = ACTIONS(43),
    [anon_sym_force_DASHpersist] = ACTIONS(43),
    [anon_sym_ignore_DASHpersist] = ACTIONS(43),
    [anon_sym_bind_DASHprocess] = ACTIONS(43),
    [anon_sym_default_DASHserver] = ACTIONS(43),
    [anon_sym_log_DASHformat] = ACTIONS(43),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(43),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(43),
    [anon_sym_nameserver] = ACTIONS(43),
    [anon_sym_peer] = ACTIONS(43),
    [anon_sym_resolution_pool_size] = ACTIONS(43),
    [anon_sym_resolve_retries] = ACTIONS(43),
    [anon_sym_reqadd] = ACTIONS(43),
    [anon_sym_reqallow] = ACTIONS(43),
    [anon_sym_reqdel] = ACTIONS(43),
    [anon_sym_reqdeny] = ACTIONS(43),
    [anon_sym_reqiallow] = ACTIONS(43),
    [anon_sym_reqidel] = ACTIONS(43),
    [anon_sym_reqideny] = ACTIONS(43),
    [anon_sym_reqipass] = ACTIONS(43),
    [anon_sym_reqirep] = ACTIONS(43),
    [anon_sym_reqisetbe] = ACTIONS(43),
    [anon_sym_reqitarpit] = ACTIONS(43),
    [anon_sym_reqpass] = ACTIONS(43),
    [anon_sym_reqrep] = ACTIONS(43),
    [anon_sym_reqsetbe] = ACTIONS(43),
    [anon_sym_reqtarpit] = ACTIONS(43),
    [anon_sym_rspadd] = ACTIONS(43),
    [anon_sym_rspdel] = ACTIONS(43),
    [anon_sym_rspdeny] = ACTIONS(43),
    [anon_sym_rspidel] = ACTIONS(43),
    [anon_sym_rspideny] = ACTIONS(43),
    [anon_sym_rspirep] = ACTIONS(43),
    [anon_sym_rsprep] = ACTIONS(43),
    [anon_sym_option] = ACTIONS(43),
    [anon_sym_timeout] = ACTIONS(43),
    [anon_sym_stats] = ACTIONS(43),
    [anon_sym_http_DASHrequest] = ACTIONS(43),
    [anon_sym_http_DASHresponse] = ACTIONS(43),
    [anon_sym_http_DASHcheck] = ACTIONS(43),
    [anon_sym_tcp_DASHrequest] = ACTIONS(43),
    [anon_sym_tcp_DASHresponse] = ACTIONS(43),
    [anon_sym_stick] = ACTIONS(43),
    [anon_sym_stick_DASHtable] = ACTIONS(43),
    [anon_sym_capture] = ACTIONS(43),
    [anon_sym_use_DASHserver] = ACTIONS(43),
    [anon_sym_monitor] = ACTIONS(43),
    [anon_sym_rate_DASHlimit] = ACTIONS(43),
    [anon_sym_persist] = ACTIONS(43),
    [sym_string] = ACTIONS(45),
    [sym_ip_address] = ACTIONS(45),
    [sym_wildcard_bind] = ACTIONS(45),
    [sym_number] = ACTIONS(47),
    [sym_time_value] = ACTIONS(45),
    [sym_parameter] = ACTIONS(45),
    [anon_sym_or] = ACTIONS(49),
    [anon_sym_PIPE_PIPE] = ACTIONS(51),
    [anon_sym_BANG] = ACTIONS(51),
    [anon_sym_if] = ACTIONS(53),
    [anon_sym_unless] = ACTIONS(53),
    [anon_sym_rewrite] = ACTIONS(53),
    [sym_identifier] = ACTIONS(47),
    [sym_path] = ACTIONS(45),
  },
  [3] = {
    [sym__argument] = STATE(4),
    [sym_operator] = STATE(4),
    [sym_control_flow] = STATE(4),
    [aux_sym_arguments_repeat1] = STATE(4),
    [ts_builtin_sym_end] = ACTIONS(55),
    [sym_comment] = ACTIONS(55),
    [anon_sym_global] = ACTIONS(57),
    [anon_sym_defaults] = ACTIONS(57),
    [anon_sym_frontend] = ACTIONS(57),
    [anon_sym_backend] = ACTIONS(57),
    [anon_sym_listen] = ACTIONS(57),
    [anon_sym_peers] = ACTIONS(57),
    [anon_sym_resolvers] = ACTIONS(57),
    [anon_sym_userlist] = ACTIONS(57),
    [anon_sym_aggregations] = ACTIONS(57),
    [anon_sym_acl] = ACTIONS(57),
    [anon_sym_bind] = ACTIONS(57),
    [anon_sym_server] = ACTIONS(57),
    [anon_sym_balance] = ACTIONS(57),
    [anon_sym_mode] = ACTIONS(57),
    [anon_sym_maxconn] = ACTIONS(57),
    [anon_sym_user] = ACTIONS(57),
    [anon_sym_group] = ACTIONS(57),
    [anon_sym_daemon] = ACTIONS(57),
    [anon_sym_log] = ACTIONS(57),
    [anon_sym_retries] = ACTIONS(57),
    [anon_sym_cookie] = ACTIONS(57),
    [anon_sym_errorfile] = ACTIONS(57),
    [anon_sym_default_backend] = ACTIONS(57),
    [anon_sym_use_backend] = ACTIONS(57),
    [anon_sym_compression] = ACTIONS(57),
    [anon_sym_redirect] = ACTIONS(57),
    [anon_sym_source] = ACTIONS(57),
    [anon_sym_id] = ACTIONS(57),
    [anon_sym_disabled] = ACTIONS(57),
    [anon_sym_enabled] = ACTIONS(57),
    [anon_sym_dispatch] = ACTIONS(57),
    [anon_sym_backlog] = ACTIONS(57),
    [anon_sym_description] = ACTIONS(57),
    [anon_sym_chroot] = ACTIONS(57),
    [anon_sym_ca_DASHbase] = ACTIONS(57),
    [anon_sym_crt_DASHbase] = ACTIONS(57),
    [anon_sym_nbproc] = ACTIONS(57),
    [anon_sym_cpu_DASHmap] = ACTIONS(57),
    [anon_sym_lua_DASHload] = ACTIONS(57),
    [anon_sym_monitor_DASHnet] = ACTIONS(57),
    [anon_sym_monitor_DASHuri] = ACTIONS(57),
    [anon_sym_grace] = ACTIONS(57),
    [anon_sym_hash_DASHtype] = ACTIONS(57),
    [anon_sym_force_DASHpersist] = ACTIONS(57),
    [anon_sym_ignore_DASHpersist] = ACTIONS(57),
    [anon_sym_bind_DASHprocess] = ACTIONS(57),
    [anon_sym_default_DASHserver] = ACTIONS(57),
    [anon_sym_log_DASHformat] = ACTIONS(57),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(57),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(57),
    [anon_sym_nameserver] = ACTIONS(57),
    [anon_sym_peer] = ACTIONS(57),
    [anon_sym_resolution_pool_size] = ACTIONS(57),
    [anon_sym_resolve_retries] = ACTIONS(57),
    [anon_sym_reqadd] = ACTIONS(57),
    [anon_sym_reqallow] = ACTIONS(57),
    [anon_sym_reqdel] = ACTIONS(57),
    [anon_sym_reqdeny] = ACTIONS(57),
    [anon_sym_reqiallow] = ACTIONS(57),
    [anon_sym_reqidel] = ACTIONS(57),
    [anon_sym_reqideny] = ACTIONS(57),
    [anon_sym_reqipass] = ACTIONS(57),
    [anon_sym_reqirep] = ACTIONS(57),
    [anon_sym_reqisetbe] = ACTIONS(57),
    [anon_sym_reqitarpit] = ACTIONS(57),
    [anon_sym_reqpass] = ACTIONS(57),
    [anon_sym_reqrep] = ACTIONS(57),
    [anon_sym_reqsetbe] = ACTIONS(57),
    [anon_sym_reqtarpit] = ACTIONS(57),
    [anon_sym_rspadd] = ACTIONS(57),
    [anon_sym_rspdel] = ACTIONS(57),
    [anon_sym_rspdeny] = ACTIONS(57),
    [anon_sym_rspidel] = ACTIONS(57),
    [anon_sym_rspideny] = ACTIONS(57),
    [anon_sym_rspirep] = ACTIONS(57),
    [anon_sym_rsprep] = ACTIONS(57),
    [anon_sym_option] = ACTIONS(57),
    [anon_sym_timeout] = ACTIONS(57),
    [anon_sym_stats] = ACTIONS(57),
    [anon_sym_http_DASHrequest] = ACTIONS(57),
    [anon_sym_http_DASHresponse] = ACTIONS(57),
    [anon_sym_http_DASHcheck] = ACTIONS(57),
    [anon_sym_tcp_DASHrequest] = ACTIONS(57),
    [anon_sym_tcp_DASHresponse] = ACTIONS(57),
    [anon_sym_stick] = ACTIONS(57),
    [anon_sym_stick_DASHtable] = ACTIONS(57),
    [anon_sym_capture] = ACTIONS(57),
    [anon_sym_use_DASHserver] = ACTIONS(57),
    [anon_sym_monitor] = ACTIONS(57),
    [anon_sym_rate_DASHlimit] = ACTIONS(57),
    [anon_sym_persist] = ACTIONS(57),
    [sym_string] = ACTIONS(59),
    [sym_ip_address] = ACTIONS(59),
    [sym_wildcard_bind] = ACTIONS(59),
    [sym_number] = ACTIONS(61),
    [sym_time_value] = ACTIONS(59),
    [sym_parameter] = ACTIONS(59),
    [anon_sym_or] = ACTIONS(49),
    [anon_sym_PIPE_PIPE] = ACTIONS(51),
    [anon_sym_BANG] = ACTIONS(51),
    [anon_sym_if] = ACTIONS(53),
    [anon_sym_unless] = ACTIONS(53),
    [anon_sym_rewrite] = ACTIONS(53),
    [sym_identifier] = ACTIONS(61),
    [sym_path] = ACTIONS(59),
  },
  [4] = {
    [sym__argument] = STATE(4),
    [sym_operator] = STATE(4),
    [sym_control_flow] = STATE(4),
    [aux_sym_arguments_repeat1] = STATE(4),
    [ts_builtin_sym_end] = ACTIONS(63),
    [sym_comment] = ACTIONS(63),
    [anon_sym_global] = ACTIONS(65),
    [anon_sym_defaults] = ACTIONS(65),
    [anon_sym_frontend] = ACTIONS(65),
    [anon_sym_backend] = ACTIONS(65),
    [anon_sym_listen] = ACTIONS(65),
    [anon_sym_peers] = ACTIONS(65),
    [anon_sym_resolvers] = ACTIONS(65),
    [anon_sym_userlist] = ACTIONS(65),
    [anon_sym_aggregations] = ACTIONS(65),
    [anon_sym_acl] = ACTIONS(65),
    [anon_sym_bind] = ACTIONS(65),
    [anon_sym_server] = ACTIONS(65),
    [anon_sym_balance] = ACTIONS(65),
    [anon_sym_mode] = ACTIONS(65),
    [anon_sym_maxconn] = ACTIONS(65),
    [anon_sym_user] = ACTIONS(65),
    [anon_sym_group] = ACTIONS(65),
    [anon_sym_daemon] = ACTIONS(65),
    [anon_sym_log] = ACTIONS(65),
    [anon_sym_retries] = ACTIONS(65),
    [anon_sym_cookie] = ACTIONS(65),
    [anon_sym_errorfile] = ACTIONS(65),
    [anon_sym_default_backend] = ACTIONS(65),
    [anon_sym_use_backend] = ACTIONS(65),
    [anon_sym_compression] = ACTIONS(65),
    [anon_sym_redirect] = ACTIONS(65),
    [anon_sym_source] = ACTIONS(65),
    [anon_sym_id] = ACTIONS(65),
    [anon_sym_disabled] = ACTIONS(65),
    [anon_sym_enabled] = ACTIONS(65),
    [anon_sym_dispatch] = ACTIONS(65),
    [anon_sym_backlog] = ACTIONS(65),
    [anon_sym_description] = ACTIONS(65),
    [anon_sym_chroot] = ACTIONS(65),
    [anon_sym_ca_DASHbase] = ACTIONS(65),
    [anon_sym_crt_DASHbase] = ACTIONS(65),
    [anon_sym_nbproc] = ACTIONS(65),
    [anon_sym_cpu_DASHmap] = ACTIONS(65),
    [anon_sym_lua_DASHload] = ACTIONS(65),
    [anon_sym_monitor_DASHnet] = ACTIONS(65),
    [anon_sym_monitor_DASHuri] = ACTIONS(65),
    [anon_sym_grace] = ACTIONS(65),
    [anon_sym_hash_DASHtype] = ACTIONS(65),
    [anon_sym_force_DASHpersist] = ACTIONS(65),
    [anon_sym_ignore_DASHpersist] = ACTIONS(65),
    [anon_sym_bind_DASHprocess] = ACTIONS(65),
    [anon_sym_default_DASHserver] = ACTIONS(65),
    [anon_sym_log_DASHformat] = ACTIONS(65),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(65),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(65),
    [anon_sym_nameserver] = ACTIONS(65),
    [anon_sym_peer] = ACTIONS(65),
    [anon_sym_resolution_pool_size] = ACTIONS(65),
    [anon_sym_resolve_retries] = ACTIONS(65),
    [anon_sym_reqadd] = ACTIONS(65),
    [anon_sym_reqallow] = ACTIONS(65),
    [anon_sym_reqdel] = ACTIONS(65),
    [anon_sym_reqdeny] = ACTIONS(65),
    [anon_sym_reqiallow] = ACTIONS(65),
    [anon_sym_reqidel] = ACTIONS(65),
    [anon_sym_reqideny] = ACTIONS(65),
    [anon_sym_reqipass] = ACTIONS(65),
    [anon_sym_reqirep] = ACTIONS(65),
    [anon_sym_reqisetbe] = ACTIONS(65),
    [anon_sym_reqitarpit] = ACTIONS(65),
    [anon_sym_reqpass] = ACTIONS(65),
    [anon_sym_reqrep] = ACTIONS(65),
    [anon_sym_reqsetbe] = ACTIONS(65),
    [anon_sym_reqtarpit] = ACTIONS(65),
    [anon_sym_rspadd] = ACTIONS(65),
    [anon_sym_rspdel] = ACTIONS(65),
    [anon_sym_rspdeny] = ACTIONS(65),
    [anon_sym_rspidel] = ACTIONS(65),
    [anon_sym_rspideny] = ACTIONS(65),
    [anon_sym_rspirep] = ACTIONS(65),
    [anon_sym_rsprep] = ACTIONS(65),
    [anon_sym_option] = ACTIONS(65),
    [anon_sym_timeout] = ACTIONS(65),
    [anon_sym_stats] = ACTIONS(65),
    [anon_sym_http_DASHrequest] = ACTIONS(65),
    [anon_sym_http_DASHresponse] = ACTIONS(65),
    [anon_sym_http_DASHcheck] = ACTIONS(65),
    [anon_sym_tcp_DASHrequest] = ACTIONS(65),
    [anon_sym_tcp_DASHresponse] = ACTIONS(65),
    [anon_sym_stick] = ACTIONS(65),
    [anon_sym_stick_DASHtable] = ACTIONS(65),
    [anon_sym_capture] = ACTIONS(65),
    [anon_sym_use_DASHserver] = ACTIONS(65),
    [anon_sym_monitor] = ACTIONS(65),
    [anon_sym_rate_DASHlimit] = ACTIONS(65),
    [anon_sym_persist] = ACTIONS(65),
    [sym_string] = ACTIONS(67),
    [sym_ip_address] = ACTIONS(67),
    [sym_wildcard_bind] = ACTIONS(67),
    [sym_number] = ACTIONS(70),
    [sym_time_value] = ACTIONS(67),
    [sym_parameter] = ACTIONS(67),
    [anon_sym_or] = ACTIONS(73),
    [anon_sym_PIPE_PIPE] = ACTIONS(76),
    [anon_sym_BANG] = ACTIONS(76),
    [anon_sym_if] = ACTIONS(79),
    [anon_sym_unless] = ACTIONS(79),
    [anon_sym_rewrite] = ACTIONS(79),
    [sym_identifier] = ACTIONS(70),
    [sym_path] = ACTIONS(67),
  },
  [5] = {
    [sym__argument] = STATE(4),
    [sym_operator] = STATE(4),
    [sym_control_flow] = STATE(4),
    [aux_sym_arguments_repeat1] = STATE(4),
    [ts_builtin_sym_end] = ACTIONS(55),
    [sym_comment] = ACTIONS(55),
    [anon_sym_global] = ACTIONS(57),
    [anon_sym_defaults] = ACTIONS(57),
    [anon_sym_frontend] = ACTIONS(57),
    [anon_sym_backend] = ACTIONS(57),
    [anon_sym_listen] = ACTIONS(57),
    [anon_sym_peers] = ACTIONS(57),
    [anon_sym_resolvers] = ACTIONS(57),
    [anon_sym_userlist] = ACTIONS(57),
    [anon_sym_aggregations] = ACTIONS(57),
    [anon_sym_acl] = ACTIONS(57),
    [anon_sym_bind] = ACTIONS(57),
    [anon_sym_server] = ACTIONS(57),
    [anon_sym_balance] = ACTIONS(57),
    [anon_sym_mode] = ACTIONS(57),
    [anon_sym_maxconn] = ACTIONS(57),
    [anon_sym_user] = ACTIONS(57),
    [anon_sym_group] = ACTIONS(57),
    [anon_sym_daemon] = ACTIONS(57),
    [anon_sym_log] = ACTIONS(57),
    [anon_sym_retries] = ACTIONS(57),
    [anon_sym_cookie] = ACTIONS(57),
    [anon_sym_errorfile] = ACTIONS(57),
    [anon_sym_default_backend] = ACTIONS(57),
    [anon_sym_use_backend] = ACTIONS(57),
    [anon_sym_compression] = ACTIONS(57),
    [anon_sym_redirect] = ACTIONS(57),
    [anon_sym_source] = ACTIONS(57),
    [anon_sym_id] = ACTIONS(57),
    [anon_sym_disabled] = ACTIONS(57),
    [anon_sym_enabled] = ACTIONS(57),
    [anon_sym_dispatch] = ACTIONS(57),
    [anon_sym_backlog] = ACTIONS(57),
    [anon_sym_description] = ACTIONS(57),
    [anon_sym_chroot] = ACTIONS(57),
    [anon_sym_ca_DASHbase] = ACTIONS(57),
    [anon_sym_crt_DASHbase] = ACTIONS(57),
    [anon_sym_nbproc] = ACTIONS(57),
    [anon_sym_cpu_DASHmap] = ACTIONS(57),
    [anon_sym_lua_DASHload] = ACTIONS(57),
    [anon_sym_monitor_DASHnet] = ACTIONS(57),
    [anon_sym_monitor_DASHuri] = ACTIONS(57),
    [anon_sym_grace] = ACTIONS(57),
    [anon_sym_hash_DASHtype] = ACTIONS(57),
    [anon_sym_force_DASHpersist] = ACTIONS(57),
    [anon_sym_ignore_DASHpersist] = ACTIONS(57),
    [anon_sym_bind_DASHprocess] = ACTIONS(57),
    [anon_sym_default_DASHserver] = ACTIONS(57),
    [anon_sym_log_DASHformat] = ACTIONS(57),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(57),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(57),
    [anon_sym_nameserver] = ACTIONS(57),
    [anon_sym_peer] = ACTIONS(57),
    [anon_sym_resolution_pool_size] = ACTIONS(57),
    [anon_sym_resolve_retries] = ACTIONS(57),
    [anon_sym_reqadd] = ACTIONS(57),
    [anon_sym_reqallow] = ACTIONS(57),
    [anon_sym_reqdel] = ACTIONS(57),
    [anon_sym_reqdeny] = ACTIONS(57),
    [anon_sym_reqiallow] = ACTIONS(57),
    [anon_sym_reqidel] = ACTIONS(57),
    [anon_sym_reqideny] = ACTIONS(57),
    [anon_sym_reqipass] = ACTIONS(57),
    [anon_sym_reqirep] = ACTIONS(57),
    [anon_sym_reqisetbe] = ACTIONS(57),
    [anon_sym_reqitarpit] = ACTIONS(57),
    [anon_sym_reqpass] = ACTIONS(57),
    [anon_sym_reqrep] = ACTIONS(57),
    [anon_sym_reqsetbe] = ACTIONS(57),
    [anon_sym_reqtarpit] = ACTIONS(57),
    [anon_sym_rspadd] = ACTIONS(57),
    [anon_sym_rspdel] = ACTIONS(57),
    [anon_sym_rspdeny] = ACTIONS(57),
    [anon_sym_rspidel] = ACTIONS(57),
    [anon_sym_rspideny] = ACTIONS(57),
    [anon_sym_rspirep] = ACTIONS(57),
    [anon_sym_rsprep] = ACTIONS(57),
    [anon_sym_option] = ACTIONS(57),
    [anon_sym_timeout] = ACTIONS(57),
    [anon_sym_stats] = ACTIONS(57),
    [anon_sym_http_DASHrequest] = ACTIONS(57),
    [anon_sym_http_DASHresponse] = ACTIONS(57),
    [anon_sym_http_DASHcheck] = ACTIONS(57),
    [anon_sym_tcp_DASHrequest] = ACTIONS(57),
    [anon_sym_tcp_DASHresponse] = ACTIONS(57),
    [anon_sym_stick] = ACTIONS(57),
    [anon_sym_stick_DASHtable] = ACTIONS(57),
    [anon_sym_capture] = ACTIONS(57),
    [anon_sym_use_DASHserver] = ACTIONS(57),
    [anon_sym_monitor] = ACTIONS(57),
    [anon_sym_rate_DASHlimit] = ACTIONS(57),
    [anon_sym_persist] = ACTIONS(57),
    [sym_string] = ACTIONS(82),
    [sym_ip_address] = ACTIONS(82),
    [sym_wildcard_bind] = ACTIONS(82),
    [sym_number] = ACTIONS(85),
    [sym_time_value] = ACTIONS(82),
    [sym_parameter] = ACTIONS(82),
    [anon_sym_or] = ACTIONS(88),
    [anon_sym_PIPE_PIPE] = ACTIONS(91),
    [anon_sym_BANG] = ACTIONS(91),
    [anon_sym_if] = ACTIONS(94),
    [anon_sym_unless] = ACTIONS(94),
    [anon_sym_rewrite] = ACTIONS(94),
    [sym_identifier] = ACTIONS(85),
    [sym_path] = ACTIONS(82),
  },
  [6] = {
    [ts_builtin_sym_end] = ACTIONS(97),
    [sym_comment] = ACTIONS(97),
    [anon_sym_global] = ACTIONS(99),
    [anon_sym_defaults] = ACTIONS(99),
    [anon_sym_frontend] = ACTIONS(99),
    [anon_sym_backend] = ACTIONS(99),
    [anon_sym_listen] = ACTIONS(99),
    [anon_sym_peers] = ACTIONS(99),
    [anon_sym_resolvers] = ACTIONS(99),
    [anon_sym_userlist] = ACTIONS(99),
    [anon_sym_aggregations] = ACTIONS(99),
    [anon_sym_acl] = ACTIONS(99),
    [anon_sym_bind] = ACTIONS(99),
    [anon_sym_server] = ACTIONS(99),
    [anon_sym_balance] = ACTIONS(99),
    [anon_sym_mode] = ACTIONS(99),
    [anon_sym_maxconn] = ACTIONS(99),
    [anon_sym_user] = ACTIONS(99),
    [anon_sym_group] = ACTIONS(99),
    [anon_sym_daemon] = ACTIONS(99),
    [anon_sym_log] = ACTIONS(99),
    [anon_sym_retries] = ACTIONS(99),
    [anon_sym_cookie] = ACTIONS(99),
    [anon_sym_errorfile] = ACTIONS(99),
    [anon_sym_default_backend] = ACTIONS(99),
    [anon_sym_use_backend] = ACTIONS(99),
    [anon_sym_compression] = ACTIONS(99),
    [anon_sym_redirect] = ACTIONS(99),
    [anon_sym_source] = ACTIONS(99),
    [anon_sym_id] = ACTIONS(99),
    [anon_sym_disabled] = ACTIONS(99),
    [anon_sym_enabled] = ACTIONS(99),
    [anon_sym_dispatch] = ACTIONS(99),
    [anon_sym_backlog] = ACTIONS(99),
    [anon_sym_description] = ACTIONS(99),
    [anon_sym_chroot] = ACTIONS(99),
    [anon_sym_ca_DASHbase] = ACTIONS(99),
    [anon_sym_crt_DASHbase] = ACTIONS(99),
    [anon_sym_nbproc] = ACTIONS(99),
    [anon_sym_cpu_DASHmap] = ACTIONS(99),
    [anon_sym_lua_DASHload] = ACTIONS(99),
    [anon_sym_monitor_DASHnet] = ACTIONS(99),
    [anon_sym_monitor_DASHuri] = ACTIONS(99),
    [anon_sym_grace] = ACTIONS(99),
    [anon_sym_hash_DASHtype] = ACTIONS(99),
    [anon_sym_force_DASHpersist] = ACTIONS(99),
    [anon_sym_ignore_DASHpersist] = ACTIONS(99),
    [anon_sym_bind_DASHprocess] = ACTIONS(99),
    [anon_sym_default_DASHserver] = ACTIONS(99),
    [anon_sym_log_DASHformat] = ACTIONS(99),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(99),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(99),
    [anon_sym_nameserver] = ACTIONS(99),
    [anon_sym_peer] = ACTIONS(99),
    [anon_sym_resolution_pool_size] = ACTIONS(99),
    [anon_sym_resolve_retries] = ACTIONS(99),
    [anon_sym_reqadd] = ACTIONS(99),
    [anon_sym_reqallow] = ACTIONS(99),
    [anon_sym_reqdel] = ACTIONS(99),
    [anon_sym_reqdeny] = ACTIONS(99),
    [anon_sym_reqiallow] = ACTIONS(99),
    [anon_sym_reqidel] = ACTIONS(99),
    [anon_sym_reqideny] = ACTIONS(99),
    [anon_sym_reqipass] = ACTIONS(99),
    [anon_sym_reqirep] = ACTIONS(99),
    [anon_sym_reqisetbe] = ACTIONS(99),
    [anon_sym_reqitarpit] = ACTIONS(99),
    [anon_sym_reqpass] = ACTIONS(99),
    [anon_sym_reqrep] = ACTIONS(99),
    [anon_sym_reqsetbe] = ACTIONS(99),
    [anon_sym_reqtarpit] = ACTIONS(99),
    [anon_sym_rspadd] = ACTIONS(99),
    [anon_sym_rspdel] = ACTIONS(99),
    [anon_sym_rspdeny] = ACTIONS(99),
    [anon_sym_rspidel] = ACTIONS(99),
    [anon_sym_rspideny] = ACTIONS(99),
    [anon_sym_rspirep] = ACTIONS(99),
    [anon_sym_rsprep] = ACTIONS(99),
    [anon_sym_option] = ACTIONS(99),
    [anon_sym_timeout] = ACTIONS(99),
    [anon_sym_stats] = ACTIONS(99),
    [anon_sym_http_DASHrequest] = ACTIONS(99),
    [anon_sym_http_DASHresponse] = ACTIONS(99),
    [anon_sym_http_DASHcheck] = ACTIONS(99),
    [anon_sym_tcp_DASHrequest] = ACTIONS(99),
    [anon_sym_tcp_DASHresponse] = ACTIONS(99),
    [anon_sym_stick] = ACTIONS(99),
    [anon_sym_stick_DASHtable] = ACTIONS(99),
    [anon_sym_capture] = ACTIONS(99),
    [anon_sym_use_DASHserver] = ACTIONS(99),
    [anon_sym_monitor] = ACTIONS(99),
    [anon_sym_rate_DASHlimit] = ACTIONS(99),
    [anon_sym_persist] = ACTIONS(99),
    [sym_string] = ACTIONS(97),
    [sym_ip_address] = ACTIONS(97),
    [sym_wildcard_bind] = ACTIONS(97),
    [sym_number] = ACTIONS(99),
    [sym_time_value] = ACTIONS(97),
    [sym_parameter] = ACTIONS(97),
    [anon_sym_or] = ACTIONS(99),
    [anon_sym_PIPE_PIPE] = ACTIONS(97),
    [anon_sym_BANG] = ACTIONS(97),
    [anon_sym_if] = ACTIONS(99),
    [anon_sym_unless] = ACTIONS(99),
    [anon_sym_rewrite] = ACTIONS(99),
    [sym_identifier] = ACTIONS(99),
    [sym_path] = ACTIONS(97),
  },
  [7] = {
    [ts_builtin_sym_end] = ACTIONS(101),
    [sym_comment] = ACTIONS(101),
    [anon_sym_global] = ACTIONS(103),
    [anon_sym_defaults] = ACTIONS(103),
    [anon_sym_frontend] = ACTIONS(103),
    [anon_sym_backend] = ACTIONS(103),
    [anon_sym_listen] = ACTIONS(103),
    [anon_sym_peers] = ACTIONS(103),
    [anon_sym_resolvers] = ACTIONS(103),
    [anon_sym_userlist] = ACTIONS(103),
    [anon_sym_aggregations] = ACTIONS(103),
    [anon_sym_acl] = ACTIONS(103),
    [anon_sym_bind] = ACTIONS(103),
    [anon_sym_server] = ACTIONS(103),
    [anon_sym_balance] = ACTIONS(103),
    [anon_sym_mode] = ACTIONS(103),
    [anon_sym_maxconn] = ACTIONS(103),
    [anon_sym_user] = ACTIONS(103),
    [anon_sym_group] = ACTIONS(103),
    [anon_sym_daemon] = ACTIONS(103),
    [anon_sym_log] = ACTIONS(103),
    [anon_sym_retries] = ACTIONS(103),
    [anon_sym_cookie] = ACTIONS(103),
    [anon_sym_errorfile] = ACTIONS(103),
    [anon_sym_default_backend] = ACTIONS(103),
    [anon_sym_use_backend] = ACTIONS(103),
    [anon_sym_compression] = ACTIONS(103),
    [anon_sym_redirect] = ACTIONS(103),
    [anon_sym_source] = ACTIONS(103),
    [anon_sym_id] = ACTIONS(103),
    [anon_sym_disabled] = ACTIONS(103),
    [anon_sym_enabled] = ACTIONS(103),
    [anon_sym_dispatch] = ACTIONS(103),
    [anon_sym_backlog] = ACTIONS(103),
    [anon_sym_description] = ACTIONS(103),
    [anon_sym_chroot] = ACTIONS(103),
    [anon_sym_ca_DASHbase] = ACTIONS(103),
    [anon_sym_crt_DASHbase] = ACTIONS(103),
    [anon_sym_nbproc] = ACTIONS(103),
    [anon_sym_cpu_DASHmap] = ACTIONS(103),
    [anon_sym_lua_DASHload] = ACTIONS(103),
    [anon_sym_monitor_DASHnet] = ACTIONS(103),
    [anon_sym_monitor_DASHuri] = ACTIONS(103),
    [anon_sym_grace] = ACTIONS(103),
    [anon_sym_hash_DASHtype] = ACTIONS(103),
    [anon_sym_force_DASHpersist] = ACTIONS(103),
    [anon_sym_ignore_DASHpersist] = ACTIONS(103),
    [anon_sym_bind_DASHprocess] = ACTIONS(103),
    [anon_sym_default_DASHserver] = ACTIONS(103),
    [anon_sym_log_DASHformat] = ACTIONS(103),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(103),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(103),
    [anon_sym_nameserver] = ACTIONS(103),
    [anon_sym_peer] = ACTIONS(103),
    [anon_sym_resolution_pool_size] = ACTIONS(103),
    [anon_sym_resolve_retries] = ACTIONS(103),
    [anon_sym_reqadd] = ACTIONS(103),
    [anon_sym_reqallow] = ACTIONS(103),
    [anon_sym_reqdel] = ACTIONS(103),
    [anon_sym_reqdeny] = ACTIONS(103),
    [anon_sym_reqiallow] = ACTIONS(103),
    [anon_sym_reqidel] = ACTIONS(103),
    [anon_sym_reqideny] = ACTIONS(103),
    [anon_sym_reqipass] = ACTIONS(103),
    [anon_sym_reqirep] = ACTIONS(103),
    [anon_sym_reqisetbe] = ACTIONS(103),
    [anon_sym_reqitarpit] = ACTIONS(103),
    [anon_sym_reqpass] = ACTIONS(103),
    [anon_sym_reqrep] = ACTIONS(103),
    [anon_sym_reqsetbe] = ACTIONS(103),
    [anon_sym_reqtarpit] = ACTIONS(103),
    [anon_sym_rspadd] = ACTIONS(103),
    [anon_sym_rspdel] = ACTIONS(103),
    [anon_sym_rspdeny] = ACTIONS(103),
    [anon_sym_rspidel] = ACTIONS(103),
    [anon_sym_rspideny] = ACTIONS(103),
    [anon_sym_rspirep] = ACTIONS(103),
    [anon_sym_rsprep] = ACTIONS(103),
    [anon_sym_option] = ACTIONS(103),
    [anon_sym_timeout] = ACTIONS(103),
    [anon_sym_stats] = ACTIONS(103),
    [anon_sym_http_DASHrequest] = ACTIONS(103),
    [anon_sym_http_DASHresponse] = ACTIONS(103),
    [anon_sym_http_DASHcheck] = ACTIONS(103),
    [anon_sym_tcp_DASHrequest] = ACTIONS(103),
    [anon_sym_tcp_DASHresponse] = ACTIONS(103),
    [anon_sym_stick] = ACTIONS(103),
    [anon_sym_stick_DASHtable] = ACTIONS(103),
    [anon_sym_capture] = ACTIONS(103),
    [anon_sym_use_DASHserver] = ACTIONS(103),
    [anon_sym_monitor] = ACTIONS(103),
    [anon_sym_rate_DASHlimit] = ACTIONS(103),
    [anon_sym_persist] = ACTIONS(103),
    [sym_string] = ACTIONS(101),
    [sym_ip_address] = ACTIONS(101),
    [sym_wildcard_bind] = ACTIONS(101),
    [sym_number] = ACTIONS(103),
    [sym_time_value] = ACTIONS(101),
    [sym_parameter] = ACTIONS(101),
    [anon_sym_or] = ACTIONS(103),
    [anon_sym_PIPE_PIPE] = ACTIONS(101),
    [anon_sym_BANG] = ACTIONS(101),
    [anon_sym_if] = ACTIONS(103),
    [anon_sym_unless] = ACTIONS(103),
    [anon_sym_rewrite] = ACTIONS(103),
    [sym_identifier] = ACTIONS(103),
    [sym_path] = ACTIONS(101),
  },
  [8] = {
    [ts_builtin_sym_end] = ACTIONS(105),
    [sym_comment] = ACTIONS(105),
    [anon_sym_global] = ACTIONS(107),
    [anon_sym_defaults] = ACTIONS(107),
    [anon_sym_frontend] = ACTIONS(107),
    [anon_sym_backend] = ACTIONS(107),
    [anon_sym_listen] = ACTIONS(107),
    [anon_sym_peers] = ACTIONS(107),
    [anon_sym_resolvers] = ACTIONS(107),
    [anon_sym_userlist] = ACTIONS(107),
    [anon_sym_aggregations] = ACTIONS(107),
    [anon_sym_acl] = ACTIONS(107),
    [anon_sym_bind] = ACTIONS(107),
    [anon_sym_server] = ACTIONS(107),
    [anon_sym_balance] = ACTIONS(107),
    [anon_sym_mode] = ACTIONS(107),
    [anon_sym_maxconn] = ACTIONS(107),
    [anon_sym_user] = ACTIONS(107),
    [anon_sym_group] = ACTIONS(107),
    [anon_sym_daemon] = ACTIONS(107),
    [anon_sym_log] = ACTIONS(107),
    [anon_sym_retries] = ACTIONS(107),
    [anon_sym_cookie] = ACTIONS(107),
    [anon_sym_errorfile] = ACTIONS(107),
    [anon_sym_default_backend] = ACTIONS(107),
    [anon_sym_use_backend] = ACTIONS(107),
    [anon_sym_compression] = ACTIONS(107),
    [anon_sym_redirect] = ACTIONS(107),
    [anon_sym_source] = ACTIONS(107),
    [anon_sym_id] = ACTIONS(107),
    [anon_sym_disabled] = ACTIONS(107),
    [anon_sym_enabled] = ACTIONS(107),
    [anon_sym_dispatch] = ACTIONS(107),
    [anon_sym_backlog] = ACTIONS(107),
    [anon_sym_description] = ACTIONS(107),
    [anon_sym_chroot] = ACTIONS(107),
    [anon_sym_ca_DASHbase] = ACTIONS(107),
    [anon_sym_crt_DASHbase] = ACTIONS(107),
    [anon_sym_nbproc] = ACTIONS(107),
    [anon_sym_cpu_DASHmap] = ACTIONS(107),
    [anon_sym_lua_DASHload] = ACTIONS(107),
    [anon_sym_monitor_DASHnet] = ACTIONS(107),
    [anon_sym_monitor_DASHuri] = ACTIONS(107),
    [anon_sym_grace] = ACTIONS(107),
    [anon_sym_hash_DASHtype] = ACTIONS(107),
    [anon_sym_force_DASHpersist] = ACTIONS(107),
    [anon_sym_ignore_DASHpersist] = ACTIONS(107),
    [anon_sym_bind_DASHprocess] = ACTIONS(107),
    [anon_sym_default_DASHserver] = ACTIONS(107),
    [anon_sym_log_DASHformat] = ACTIONS(107),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(107),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(107),
    [anon_sym_nameserver] = ACTIONS(107),
    [anon_sym_peer] = ACTIONS(107),
    [anon_sym_resolution_pool_size] = ACTIONS(107),
    [anon_sym_resolve_retries] = ACTIONS(107),
    [anon_sym_reqadd] = ACTIONS(107),
    [anon_sym_reqallow] = ACTIONS(107),
    [anon_sym_reqdel] = ACTIONS(107),
    [anon_sym_reqdeny] = ACTIONS(107),
    [anon_sym_reqiallow] = ACTIONS(107),
    [anon_sym_reqidel] = ACTIONS(107),
    [anon_sym_reqideny] = ACTIONS(107),
    [anon_sym_reqipass] = ACTIONS(107),
    [anon_sym_reqirep] = ACTIONS(107),
    [anon_sym_reqisetbe] = ACTIONS(107),
    [anon_sym_reqitarpit] = ACTIONS(107),
    [anon_sym_reqpass] = ACTIONS(107),
    [anon_sym_reqrep] = ACTIONS(107),
    [anon_sym_reqsetbe] = ACTIONS(107),
    [anon_sym_reqtarpit] = ACTIONS(107),
    [anon_sym_rspadd] = ACTIONS(107),
    [anon_sym_rspdel] = ACTIONS(107),
    [anon_sym_rspdeny] = ACTIONS(107),
    [anon_sym_rspidel] = ACTIONS(107),
    [anon_sym_rspideny] = ACTIONS(107),
    [anon_sym_rspirep] = ACTIONS(107),
    [anon_sym_rsprep] = ACTIONS(107),
    [anon_sym_option] = ACTIONS(107),
    [anon_sym_timeout] = ACTIONS(107),
    [anon_sym_stats] = ACTIONS(107),
    [anon_sym_http_DASHrequest] = ACTIONS(107),
    [anon_sym_http_DASHresponse] = ACTIONS(107),
    [anon_sym_http_DASHcheck] = ACTIONS(107),
    [anon_sym_tcp_DASHrequest] = ACTIONS(107),
    [anon_sym_tcp_DASHresponse] = ACTIONS(107),
    [anon_sym_stick] = ACTIONS(107),
    [anon_sym_stick_DASHtable] = ACTIONS(107),
    [anon_sym_capture] = ACTIONS(107),
    [anon_sym_use_DASHserver] = ACTIONS(107),
    [anon_sym_monitor] = ACTIONS(107),
    [anon_sym_rate_DASHlimit] = ACTIONS(107),
    [anon_sym_persist] = ACTIONS(107),
    [sym_string] = ACTIONS(105),
    [sym_ip_address] = ACTIONS(105),
    [sym_wildcard_bind] = ACTIONS(105),
    [sym_number] = ACTIONS(107),
    [sym_time_value] = ACTIONS(105),
    [sym_parameter] = ACTIONS(105),
    [anon_sym_or] = ACTIONS(107),
    [anon_sym_PIPE_PIPE] = ACTIONS(105),
    [anon_sym_BANG] = ACTIONS(105),
    [anon_sym_if] = ACTIONS(107),
    [anon_sym_unless] = ACTIONS(107),
    [anon_sym_rewrite] = ACTIONS(107),
    [sym_identifier] = ACTIONS(107),
    [sym_path] = ACTIONS(105),
  },
  [9] = {
    [ts_builtin_sym_end] = ACTIONS(109),
    [sym_comment] = ACTIONS(109),
    [anon_sym_global] = ACTIONS(111),
    [anon_sym_defaults] = ACTIONS(111),
    [anon_sym_frontend] = ACTIONS(111),
    [anon_sym_backend] = ACTIONS(111),
    [anon_sym_listen] = ACTIONS(111),
    [anon_sym_peers] = ACTIONS(111),
    [anon_sym_resolvers] = ACTIONS(111),
    [anon_sym_userlist] = ACTIONS(111),
    [anon_sym_aggregations] = ACTIONS(111),
    [anon_sym_acl] = ACTIONS(111),
    [anon_sym_bind] = ACTIONS(111),
    [anon_sym_server] = ACTIONS(111),
    [anon_sym_balance] = ACTIONS(111),
    [anon_sym_mode] = ACTIONS(111),
    [anon_sym_maxconn] = ACTIONS(111),
    [anon_sym_user] = ACTIONS(111),
    [anon_sym_group] = ACTIONS(111),
    [anon_sym_daemon] = ACTIONS(111),
    [anon_sym_log] = ACTIONS(111),
    [anon_sym_retries] = ACTIONS(111),
    [anon_sym_cookie] = ACTIONS(111),
    [anon_sym_errorfile] = ACTIONS(111),
    [anon_sym_default_backend] = ACTIONS(111),
    [anon_sym_use_backend] = ACTIONS(111),
    [anon_sym_compression] = ACTIONS(111),
    [anon_sym_redirect] = ACTIONS(111),
    [anon_sym_source] = ACTIONS(111),
    [anon_sym_id] = ACTIONS(111),
    [anon_sym_disabled] = ACTIONS(111),
    [anon_sym_enabled] = ACTIONS(111),
    [anon_sym_dispatch] = ACTIONS(111),
    [anon_sym_backlog] = ACTIONS(111),
    [anon_sym_description] = ACTIONS(111),
    [anon_sym_chroot] = ACTIONS(111),
    [anon_sym_ca_DASHbase] = ACTIONS(111),
    [anon_sym_crt_DASHbase] = ACTIONS(111),
    [anon_sym_nbproc] = ACTIONS(111),
    [anon_sym_cpu_DASHmap] = ACTIONS(111),
    [anon_sym_lua_DASHload] = ACTIONS(111),
    [anon_sym_monitor_DASHnet] = ACTIONS(111),
    [anon_sym_monitor_DASHuri] = ACTIONS(111),
    [anon_sym_grace] = ACTIONS(111),
    [anon_sym_hash_DASHtype] = ACTIONS(111),
    [anon_sym_force_DASHpersist] = ACTIONS(111),
    [anon_sym_ignore_DASHpersist] = ACTIONS(111),
    [anon_sym_bind_DASHprocess] = ACTIONS(111),
    [anon_sym_default_DASHserver] = ACTIONS(111),
    [anon_sym_log_DASHformat] = ACTIONS(111),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(111),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(111),
    [anon_sym_nameserver] = ACTIONS(111),
    [anon_sym_peer] = ACTIONS(111),
    [anon_sym_resolution_pool_size] = ACTIONS(111),
    [anon_sym_resolve_retries] = ACTIONS(111),
    [anon_sym_reqadd] = ACTIONS(111),
    [anon_sym_reqallow] = ACTIONS(111),
    [anon_sym_reqdel] = ACTIONS(111),
    [anon_sym_reqdeny] = ACTIONS(111),
    [anon_sym_reqiallow] = ACTIONS(111),
    [anon_sym_reqidel] = ACTIONS(111),
    [anon_sym_reqideny] = ACTIONS(111),
    [anon_sym_reqipass] = ACTIONS(111),
    [anon_sym_reqirep] = ACTIONS(111),
    [anon_sym_reqisetbe] = ACTIONS(111),
    [anon_sym_reqitarpit] = ACTIONS(111),
    [anon_sym_reqpass] = ACTIONS(111),
    [anon_sym_reqrep] = ACTIONS(111),
    [anon_sym_reqsetbe] = ACTIONS(111),
    [anon_sym_reqtarpit] = ACTIONS(111),
    [anon_sym_rspadd] = ACTIONS(111),
    [anon_sym_rspdel] = ACTIONS(111),
    [anon_sym_rspdeny] = ACTIONS(111),
    [anon_sym_rspidel] = ACTIONS(111),
    [anon_sym_rspideny] = ACTIONS(111),
    [anon_sym_rspirep] = ACTIONS(111),
    [anon_sym_rsprep] = ACTIONS(111),
    [anon_sym_option] = ACTIONS(111),
    [anon_sym_timeout] = ACTIONS(111),
    [anon_sym_stats] = ACTIONS(111),
    [anon_sym_http_DASHrequest] = ACTIONS(111),
    [anon_sym_http_DASHresponse] = ACTIONS(111),
    [anon_sym_http_DASHcheck] = ACTIONS(111),
    [anon_sym_tcp_DASHrequest] = ACTIONS(111),
    [anon_sym_tcp_DASHresponse] = ACTIONS(111),
    [anon_sym_stick] = ACTIONS(111),
    [anon_sym_stick_DASHtable] = ACTIONS(111),
    [anon_sym_capture] = ACTIONS(111),
    [anon_sym_use_DASHserver] = ACTIONS(111),
    [anon_sym_monitor] = ACTIONS(111),
    [anon_sym_rate_DASHlimit] = ACTIONS(111),
    [anon_sym_persist] = ACTIONS(111),
    [sym_string] = ACTIONS(109),
    [sym_ip_address] = ACTIONS(109),
    [sym_wildcard_bind] = ACTIONS(109),
    [sym_number] = ACTIONS(111),
    [sym_time_value] = ACTIONS(109),
    [sym_parameter] = ACTIONS(109),
    [anon_sym_or] = ACTIONS(111),
    [anon_sym_PIPE_PIPE] = ACTIONS(109),
    [anon_sym_BANG] = ACTIONS(109),
    [anon_sym_if] = ACTIONS(111),
    [anon_sym_unless] = ACTIONS(111),
    [anon_sym_rewrite] = ACTIONS(111),
    [sym_identifier] = ACTIONS(111),
    [sym_path] = ACTIONS(109),
  },
  [10] = {
    [ts_builtin_sym_end] = ACTIONS(113),
    [sym_comment] = ACTIONS(113),
    [anon_sym_global] = ACTIONS(115),
    [anon_sym_defaults] = ACTIONS(115),
    [anon_sym_frontend] = ACTIONS(115),
    [anon_sym_backend] = ACTIONS(115),
    [anon_sym_listen] = ACTIONS(115),
    [anon_sym_peers] = ACTIONS(115),
    [anon_sym_resolvers] = ACTIONS(115),
    [anon_sym_userlist] = ACTIONS(115),
    [anon_sym_aggregations] = ACTIONS(115),
    [anon_sym_acl] = ACTIONS(115),
    [anon_sym_bind] = ACTIONS(115),
    [anon_sym_server] = ACTIONS(115),
    [anon_sym_balance] = ACTIONS(115),
    [anon_sym_mode] = ACTIONS(115),
    [anon_sym_maxconn] = ACTIONS(115),
    [anon_sym_user] = ACTIONS(115),
    [anon_sym_group] = ACTIONS(115),
    [anon_sym_daemon] = ACTIONS(115),
    [anon_sym_log] = ACTIONS(115),
    [anon_sym_retries] = ACTIONS(115),
    [anon_sym_cookie] = ACTIONS(115),
    [anon_sym_errorfile] = ACTIONS(115),
    [anon_sym_default_backend] = ACTIONS(115),
    [anon_sym_use_backend] = ACTIONS(115),
    [anon_sym_compression] = ACTIONS(115),
    [anon_sym_redirect] = ACTIONS(115),
    [anon_sym_source] = ACTIONS(115),
    [anon_sym_id] = ACTIONS(115),
    [anon_sym_disabled] = ACTIONS(115),
    [anon_sym_enabled] = ACTIONS(115),
    [anon_sym_dispatch] = ACTIONS(115),
    [anon_sym_backlog] = ACTIONS(115),
    [anon_sym_description] = ACTIONS(115),
    [anon_sym_chroot] = ACTIONS(115),
    [anon_sym_ca_DASHbase] = ACTIONS(115),
    [anon_sym_crt_DASHbase] = ACTIONS(115),
    [anon_sym_nbproc] = ACTIONS(115),
    [anon_sym_cpu_DASHmap] = ACTIONS(115),
    [anon_sym_lua_DASHload] = ACTIONS(115),
    [anon_sym_monitor_DASHnet] = ACTIONS(115),
    [anon_sym_monitor_DASHuri] = ACTIONS(115),
    [anon_sym_grace] = ACTIONS(115),
    [anon_sym_hash_DASHtype] = ACTIONS(115),
    [anon_sym_force_DASHpersist] = ACTIONS(115),
    [anon_sym_ignore_DASHpersist] = ACTIONS(115),
    [anon_sym_bind_DASHprocess] = ACTIONS(115),
    [anon_sym_default_DASHserver] = ACTIONS(115),
    [anon_sym_log_DASHformat] = ACTIONS(115),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(115),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(115),
    [anon_sym_nameserver] = ACTIONS(115),
    [anon_sym_peer] = ACTIONS(115),
    [anon_sym_resolution_pool_size] = ACTIONS(115),
    [anon_sym_resolve_retries] = ACTIONS(115),
    [anon_sym_reqadd] = ACTIONS(115),
    [anon_sym_reqallow] = ACTIONS(115),
    [anon_sym_reqdel] = ACTIONS(115),
    [anon_sym_reqdeny] = ACTIONS(115),
    [anon_sym_reqiallow] = ACTIONS(115),
    [anon_sym_reqidel] = ACTIONS(115),
    [anon_sym_reqideny] = ACTIONS(115),
    [anon_sym_reqipass] = ACTIONS(115),
    [anon_sym_reqirep] = ACTIONS(115),
    [anon_sym_reqisetbe] = ACTIONS(115),
    [anon_sym_reqitarpit] = ACTIONS(115),
    [anon_sym_reqpass] = ACTIONS(115),
    [anon_sym_reqrep] = ACTIONS(115),
    [anon_sym_reqsetbe] = ACTIONS(115),
    [anon_sym_reqtarpit] = ACTIONS(115),
    [anon_sym_rspadd] = ACTIONS(115),
    [anon_sym_rspdel] = ACTIONS(115),
    [anon_sym_rspdeny] = ACTIONS(115),
    [anon_sym_rspidel] = ACTIONS(115),
    [anon_sym_rspideny] = ACTIONS(115),
    [anon_sym_rspirep] = ACTIONS(115),
    [anon_sym_rsprep] = ACTIONS(115),
    [anon_sym_option] = ACTIONS(115),
    [anon_sym_timeout] = ACTIONS(115),
    [anon_sym_stats] = ACTIONS(115),
    [anon_sym_http_DASHrequest] = ACTIONS(115),
    [anon_sym_http_DASHresponse] = ACTIONS(115),
    [anon_sym_http_DASHcheck] = ACTIONS(115),
    [anon_sym_tcp_DASHrequest] = ACTIONS(115),
    [anon_sym_tcp_DASHresponse] = ACTIONS(115),
    [anon_sym_stick] = ACTIONS(115),
    [anon_sym_stick_DASHtable] = ACTIONS(115),
    [anon_sym_capture] = ACTIONS(115),
    [anon_sym_use_DASHserver] = ACTIONS(115),
    [anon_sym_monitor] = ACTIONS(115),
    [anon_sym_rate_DASHlimit] = ACTIONS(115),
    [anon_sym_persist] = ACTIONS(115),
    [sym_string] = ACTIONS(113),
    [sym_ip_address] = ACTIONS(113),
    [sym_wildcard_bind] = ACTIONS(113),
    [sym_number] = ACTIONS(115),
    [sym_time_value] = ACTIONS(113),
    [sym_parameter] = ACTIONS(113),
    [anon_sym_or] = ACTIONS(115),
    [anon_sym_PIPE_PIPE] = ACTIONS(113),
    [anon_sym_BANG] = ACTIONS(113),
    [anon_sym_if] = ACTIONS(115),
    [anon_sym_unless] = ACTIONS(115),
    [anon_sym_rewrite] = ACTIONS(115),
    [sym_identifier] = ACTIONS(115),
    [sym_path] = ACTIONS(113),
  },
  [11] = {
    [ts_builtin_sym_end] = ACTIONS(117),
    [sym_comment] = ACTIONS(117),
    [anon_sym_global] = ACTIONS(119),
    [anon_sym_defaults] = ACTIONS(119),
    [anon_sym_frontend] = ACTIONS(119),
    [anon_sym_backend] = ACTIONS(119),
    [anon_sym_listen] = ACTIONS(119),
    [anon_sym_peers] = ACTIONS(119),
    [anon_sym_resolvers] = ACTIONS(119),
    [anon_sym_userlist] = ACTIONS(119),
    [anon_sym_aggregations] = ACTIONS(119),
    [anon_sym_acl] = ACTIONS(119),
    [anon_sym_bind] = ACTIONS(119),
    [anon_sym_server] = ACTIONS(119),
    [anon_sym_balance] = ACTIONS(119),
    [anon_sym_mode] = ACTIONS(119),
    [anon_sym_maxconn] = ACTIONS(119),
    [anon_sym_user] = ACTIONS(119),
    [anon_sym_group] = ACTIONS(119),
    [anon_sym_daemon] = ACTIONS(119),
    [anon_sym_log] = ACTIONS(119),
    [anon_sym_retries] = ACTIONS(119),
    [anon_sym_cookie] = ACTIONS(119),
    [anon_sym_errorfile] = ACTIONS(119),
    [anon_sym_default_backend] = ACTIONS(119),
    [anon_sym_use_backend] = ACTIONS(119),
    [anon_sym_compression] = ACTIONS(119),
    [anon_sym_redirect] = ACTIONS(119),
    [anon_sym_source] = ACTIONS(119),
    [anon_sym_id] = ACTIONS(119),
    [anon_sym_disabled] = ACTIONS(119),
    [anon_sym_enabled] = ACTIONS(119),
    [anon_sym_dispatch] = ACTIONS(119),
    [anon_sym_backlog] = ACTIONS(119),
    [anon_sym_description] = ACTIONS(119),
    [anon_sym_chroot] = ACTIONS(119),
    [anon_sym_ca_DASHbase] = ACTIONS(119),
    [anon_sym_crt_DASHbase] = ACTIONS(119),
    [anon_sym_nbproc] = ACTIONS(119),
    [anon_sym_cpu_DASHmap] = ACTIONS(119),
    [anon_sym_lua_DASHload] = ACTIONS(119),
    [anon_sym_monitor_DASHnet] = ACTIONS(119),
    [anon_sym_monitor_DASHuri] = ACTIONS(119),
    [anon_sym_grace] = ACTIONS(119),
    [anon_sym_hash_DASHtype] = ACTIONS(119),
    [anon_sym_force_DASHpersist] = ACTIONS(119),
    [anon_sym_ignore_DASHpersist] = ACTIONS(119),
    [anon_sym_bind_DASHprocess] = ACTIONS(119),
    [anon_sym_default_DASHserver] = ACTIONS(119),
    [anon_sym_log_DASHformat] = ACTIONS(119),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(119),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(119),
    [anon_sym_nameserver] = ACTIONS(119),
    [anon_sym_peer] = ACTIONS(119),
    [anon_sym_resolution_pool_size] = ACTIONS(119),
    [anon_sym_resolve_retries] = ACTIONS(119),
    [anon_sym_reqadd] = ACTIONS(119),
    [anon_sym_reqallow] = ACTIONS(119),
    [anon_sym_reqdel] = ACTIONS(119),
    [anon_sym_reqdeny] = ACTIONS(119),
    [anon_sym_reqiallow] = ACTIONS(119),
    [anon_sym_reqidel] = ACTIONS(119),
    [anon_sym_reqideny] = ACTIONS(119),
    [anon_sym_reqipass] = ACTIONS(119),
    [anon_sym_reqirep] = ACTIONS(119),
    [anon_sym_reqisetbe] = ACTIONS(119),
    [anon_sym_reqitarpit] = ACTIONS(119),
    [anon_sym_reqpass] = ACTIONS(119),
    [anon_sym_reqrep] = ACTIONS(119),
    [anon_sym_reqsetbe] = ACTIONS(119),
    [anon_sym_reqtarpit] = ACTIONS(119),
    [anon_sym_rspadd] = ACTIONS(119),
    [anon_sym_rspdel] = ACTIONS(119),
    [anon_sym_rspdeny] = ACTIONS(119),
    [anon_sym_rspidel] = ACTIONS(119),
    [anon_sym_rspideny] = ACTIONS(119),
    [anon_sym_rspirep] = ACTIONS(119),
    [anon_sym_rsprep] = ACTIONS(119),
    [anon_sym_option] = ACTIONS(119),
    [anon_sym_timeout] = ACTIONS(119),
    [anon_sym_stats] = ACTIONS(119),
    [anon_sym_http_DASHrequest] = ACTIONS(119),
    [anon_sym_http_DASHresponse] = ACTIONS(119),
    [anon_sym_http_DASHcheck] = ACTIONS(119),
    [anon_sym_tcp_DASHrequest] = ACTIONS(119),
    [anon_sym_tcp_DASHresponse] = ACTIONS(119),
    [anon_sym_stick] = ACTIONS(119),
    [anon_sym_stick_DASHtable] = ACTIONS(119),
    [anon_sym_capture] = ACTIONS(119),
    [anon_sym_use_DASHserver] = ACTIONS(119),
    [anon_sym_monitor] = ACTIONS(119),
    [anon_sym_rate_DASHlimit] = ACTIONS(119),
    [anon_sym_persist] = ACTIONS(119),
    [sym_string] = ACTIONS(117),
    [sym_ip_address] = ACTIONS(117),
    [sym_wildcard_bind] = ACTIONS(117),
    [sym_number] = ACTIONS(119),
    [sym_time_value] = ACTIONS(117),
    [sym_parameter] = ACTIONS(117),
    [anon_sym_or] = ACTIONS(119),
    [anon_sym_PIPE_PIPE] = ACTIONS(117),
    [anon_sym_BANG] = ACTIONS(117),
    [anon_sym_if] = ACTIONS(119),
    [anon_sym_unless] = ACTIONS(119),
    [anon_sym_rewrite] = ACTIONS(119),
    [sym_identifier] = ACTIONS(119),
    [sym_path] = ACTIONS(117),
  },
  [12] = {
    [ts_builtin_sym_end] = ACTIONS(121),
    [sym_comment] = ACTIONS(121),
    [anon_sym_global] = ACTIONS(123),
    [anon_sym_defaults] = ACTIONS(123),
    [anon_sym_frontend] = ACTIONS(123),
    [anon_sym_backend] = ACTIONS(123),
    [anon_sym_listen] = ACTIONS(123),
    [anon_sym_peers] = ACTIONS(123),
    [anon_sym_resolvers] = ACTIONS(123),
    [anon_sym_userlist] = ACTIONS(123),
    [anon_sym_aggregations] = ACTIONS(123),
    [anon_sym_acl] = ACTIONS(123),
    [anon_sym_bind] = ACTIONS(123),
    [anon_sym_server] = ACTIONS(123),
    [anon_sym_balance] = ACTIONS(123),
    [anon_sym_mode] = ACTIONS(123),
    [anon_sym_maxconn] = ACTIONS(123),
    [anon_sym_user] = ACTIONS(123),
    [anon_sym_group] = ACTIONS(123),
    [anon_sym_daemon] = ACTIONS(123),
    [anon_sym_log] = ACTIONS(123),
    [anon_sym_retries] = ACTIONS(123),
    [anon_sym_cookie] = ACTIONS(123),
    [anon_sym_errorfile] = ACTIONS(123),
    [anon_sym_default_backend] = ACTIONS(123),
    [anon_sym_use_backend] = ACTIONS(123),
    [anon_sym_compression] = ACTIONS(123),
    [anon_sym_redirect] = ACTIONS(123),
    [anon_sym_source] = ACTIONS(123),
    [anon_sym_id] = ACTIONS(123),
    [anon_sym_disabled] = ACTIONS(123),
    [anon_sym_enabled] = ACTIONS(123),
    [anon_sym_dispatch] = ACTIONS(123),
    [anon_sym_backlog] = ACTIONS(123),
    [anon_sym_description] = ACTIONS(123),
    [anon_sym_chroot] = ACTIONS(123),
    [anon_sym_ca_DASHbase] = ACTIONS(123),
    [anon_sym_crt_DASHbase] = ACTIONS(123),
    [anon_sym_nbproc] = ACTIONS(123),
    [anon_sym_cpu_DASHmap] = ACTIONS(123),
    [anon_sym_lua_DASHload] = ACTIONS(123),
    [anon_sym_monitor_DASHnet] = ACTIONS(123),
    [anon_sym_monitor_DASHuri] = ACTIONS(123),
    [anon_sym_grace] = ACTIONS(123),
    [anon_sym_hash_DASHtype] = ACTIONS(123),
    [anon_sym_force_DASHpersist] = ACTIONS(123),
    [anon_sym_ignore_DASHpersist] = ACTIONS(123),
    [anon_sym_bind_DASHprocess] = ACTIONS(123),
    [anon_sym_default_DASHserver] = ACTIONS(123),
    [anon_sym_log_DASHformat] = ACTIONS(123),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(123),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(123),
    [anon_sym_nameserver] = ACTIONS(123),
    [anon_sym_peer] = ACTIONS(123),
    [anon_sym_resolution_pool_size] = ACTIONS(123),
    [anon_sym_resolve_retries] = ACTIONS(123),
    [anon_sym_reqadd] = ACTIONS(123),
    [anon_sym_reqallow] = ACTIONS(123),
    [anon_sym_reqdel] = ACTIONS(123),
    [anon_sym_reqdeny] = ACTIONS(123),
    [anon_sym_reqiallow] = ACTIONS(123),
    [anon_sym_reqidel] = ACTIONS(123),
    [anon_sym_reqideny] = ACTIONS(123),
    [anon_sym_reqipass] = ACTIONS(123),
    [anon_sym_reqirep] = ACTIONS(123),
    [anon_sym_reqisetbe] = ACTIONS(123),
    [anon_sym_reqitarpit] = ACTIONS(123),
    [anon_sym_reqpass] = ACTIONS(123),
    [anon_sym_reqrep] = ACTIONS(123),
    [anon_sym_reqsetbe] = ACTIONS(123),
    [anon_sym_reqtarpit] = ACTIONS(123),
    [anon_sym_rspadd] = ACTIONS(123),
    [anon_sym_rspdel] = ACTIONS(123),
    [anon_sym_rspdeny] = ACTIONS(123),
    [anon_sym_rspidel] = ACTIONS(123),
    [anon_sym_rspideny] = ACTIONS(123),
    [anon_sym_rspirep] = ACTIONS(123),
    [anon_sym_rsprep] = ACTIONS(123),
    [anon_sym_option] = ACTIONS(123),
    [anon_sym_timeout] = ACTIONS(123),
    [anon_sym_stats] = ACTIONS(123),
    [anon_sym_http_DASHrequest] = ACTIONS(123),
    [anon_sym_http_DASHresponse] = ACTIONS(123),
    [anon_sym_http_DASHcheck] = ACTIONS(123),
    [anon_sym_tcp_DASHrequest] = ACTIONS(123),
    [anon_sym_tcp_DASHresponse] = ACTIONS(123),
    [anon_sym_stick] = ACTIONS(123),
    [anon_sym_stick_DASHtable] = ACTIONS(123),
    [anon_sym_capture] = ACTIONS(123),
    [anon_sym_use_DASHserver] = ACTIONS(123),
    [anon_sym_monitor] = ACTIONS(123),
    [anon_sym_rate_DASHlimit] = ACTIONS(123),
    [anon_sym_persist] = ACTIONS(123),
    [sym_string] = ACTIONS(121),
    [sym_ip_address] = ACTIONS(121),
    [sym_wildcard_bind] = ACTIONS(121),
    [sym_number] = ACTIONS(123),
    [sym_time_value] = ACTIONS(121),
    [sym_parameter] = ACTIONS(121),
    [anon_sym_or] = ACTIONS(123),
    [anon_sym_PIPE_PIPE] = ACTIONS(121),
    [anon_sym_BANG] = ACTIONS(121),
    [anon_sym_if] = ACTIONS(123),
    [anon_sym_unless] = ACTIONS(123),
    [anon_sym_rewrite] = ACTIONS(123),
    [sym_identifier] = ACTIONS(123),
    [sym_path] = ACTIONS(121),
  },
  [13] = {
    [ts_builtin_sym_end] = ACTIONS(125),
    [sym_comment] = ACTIONS(125),
    [anon_sym_global] = ACTIONS(127),
    [anon_sym_defaults] = ACTIONS(127),
    [anon_sym_frontend] = ACTIONS(127),
    [anon_sym_backend] = ACTIONS(127),
    [anon_sym_listen] = ACTIONS(127),
    [anon_sym_peers] = ACTIONS(127),
    [anon_sym_resolvers] = ACTIONS(127),
    [anon_sym_userlist] = ACTIONS(127),
    [anon_sym_aggregations] = ACTIONS(127),
    [anon_sym_acl] = ACTIONS(127),
    [anon_sym_bind] = ACTIONS(127),
    [anon_sym_server] = ACTIONS(127),
    [anon_sym_balance] = ACTIONS(127),
    [anon_sym_mode] = ACTIONS(127),
    [anon_sym_maxconn] = ACTIONS(127),
    [anon_sym_user] = ACTIONS(127),
    [anon_sym_group] = ACTIONS(127),
    [anon_sym_daemon] = ACTIONS(127),
    [anon_sym_log] = ACTIONS(127),
    [anon_sym_retries] = ACTIONS(127),
    [anon_sym_cookie] = ACTIONS(127),
    [anon_sym_errorfile] = ACTIONS(127),
    [anon_sym_default_backend] = ACTIONS(127),
    [anon_sym_use_backend] = ACTIONS(127),
    [anon_sym_compression] = ACTIONS(127),
    [anon_sym_redirect] = ACTIONS(127),
    [anon_sym_source] = ACTIONS(127),
    [anon_sym_id] = ACTIONS(127),
    [anon_sym_disabled] = ACTIONS(127),
    [anon_sym_enabled] = ACTIONS(127),
    [anon_sym_dispatch] = ACTIONS(127),
    [anon_sym_backlog] = ACTIONS(127),
    [anon_sym_description] = ACTIONS(127),
    [anon_sym_chroot] = ACTIONS(127),
    [anon_sym_ca_DASHbase] = ACTIONS(127),
    [anon_sym_crt_DASHbase] = ACTIONS(127),
    [anon_sym_nbproc] = ACTIONS(127),
    [anon_sym_cpu_DASHmap] = ACTIONS(127),
    [anon_sym_lua_DASHload] = ACTIONS(127),
    [anon_sym_monitor_DASHnet] = ACTIONS(127),
    [anon_sym_monitor_DASHuri] = ACTIONS(127),
    [anon_sym_grace] = ACTIONS(127),
    [anon_sym_hash_DASHtype] = ACTIONS(127),
    [anon_sym_force_DASHpersist] = ACTIONS(127),
    [anon_sym_ignore_DASHpersist] = ACTIONS(127),
    [anon_sym_bind_DASHprocess] = ACTIONS(127),
    [anon_sym_default_DASHserver] = ACTIONS(127),
    [anon_sym_log_DASHformat] = ACTIONS(127),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(127),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(127),
    [anon_sym_nameserver] = ACTIONS(127),
    [anon_sym_peer] = ACTIONS(127),
    [anon_sym_resolution_pool_size] = ACTIONS(127),
    [anon_sym_resolve_retries] = ACTIONS(127),
    [anon_sym_reqadd] = ACTIONS(127),
    [anon_sym_reqallow] = ACTIONS(127),
    [anon_sym_reqdel] = ACTIONS(127),
    [anon_sym_reqdeny] = ACTIONS(127),
    [anon_sym_reqiallow] = ACTIONS(127),
    [anon_sym_reqidel] = ACTIONS(127),
    [anon_sym_reqideny] = ACTIONS(127),
    [anon_sym_reqipass] = ACTIONS(127),
    [anon_sym_reqirep] = ACTIONS(127),
    [anon_sym_reqisetbe] = ACTIONS(127),
    [anon_sym_reqitarpit] = ACTIONS(127),
    [anon_sym_reqpass] = ACTIONS(127),
    [anon_sym_reqrep] = ACTIONS(127),
    [anon_sym_reqsetbe] = ACTIONS(127),
    [anon_sym_reqtarpit] = ACTIONS(127),
    [anon_sym_rspadd] = ACTIONS(127),
    [anon_sym_rspdel] = ACTIONS(127),
    [anon_sym_rspdeny] = ACTIONS(127),
    [anon_sym_rspidel] = ACTIONS(127),
    [anon_sym_rspideny] = ACTIONS(127),
    [anon_sym_rspirep] = ACTIONS(127),
    [anon_sym_rsprep] = ACTIONS(127),
    [anon_sym_option] = ACTIONS(127),
    [anon_sym_timeout] = ACTIONS(127),
    [anon_sym_stats] = ACTIONS(127),
    [anon_sym_http_DASHrequest] = ACTIONS(127),
    [anon_sym_http_DASHresponse] = ACTIONS(127),
    [anon_sym_http_DASHcheck] = ACTIONS(127),
    [anon_sym_tcp_DASHrequest] = ACTIONS(127),
    [anon_sym_tcp_DASHresponse] = ACTIONS(127),
    [anon_sym_stick] = ACTIONS(127),
    [anon_sym_stick_DASHtable] = ACTIONS(127),
    [anon_sym_capture] = ACTIONS(127),
    [anon_sym_use_DASHserver] = ACTIONS(127),
    [anon_sym_monitor] = ACTIONS(127),
    [anon_sym_rate_DASHlimit] = ACTIONS(127),
    [anon_sym_persist] = ACTIONS(127),
    [sym_string] = ACTIONS(125),
    [sym_ip_address] = ACTIONS(125),
    [sym_wildcard_bind] = ACTIONS(125),
    [sym_number] = ACTIONS(127),
    [sym_time_value] = ACTIONS(125),
    [sym_parameter] = ACTIONS(125),
    [anon_sym_or] = ACTIONS(127),
    [anon_sym_PIPE_PIPE] = ACTIONS(125),
    [anon_sym_BANG] = ACTIONS(125),
    [anon_sym_if] = ACTIONS(127),
    [anon_sym_unless] = ACTIONS(127),
    [anon_sym_rewrite] = ACTIONS(127),
    [sym_identifier] = ACTIONS(127),
    [sym_path] = ACTIONS(125),
  },
  [14] = {
    [ts_builtin_sym_end] = ACTIONS(129),
    [sym_comment] = ACTIONS(129),
    [anon_sym_global] = ACTIONS(131),
    [anon_sym_defaults] = ACTIONS(131),
    [anon_sym_frontend] = ACTIONS(131),
    [anon_sym_backend] = ACTIONS(131),
    [anon_sym_listen] = ACTIONS(131),
    [anon_sym_peers] = ACTIONS(131),
    [anon_sym_resolvers] = ACTIONS(131),
    [anon_sym_userlist] = ACTIONS(131),
    [anon_sym_aggregations] = ACTIONS(131),
    [anon_sym_acl] = ACTIONS(131),
    [anon_sym_bind] = ACTIONS(131),
    [anon_sym_server] = ACTIONS(131),
    [anon_sym_balance] = ACTIONS(131),
    [anon_sym_mode] = ACTIONS(131),
    [anon_sym_maxconn] = ACTIONS(131),
    [anon_sym_user] = ACTIONS(131),
    [anon_sym_group] = ACTIONS(131),
    [anon_sym_daemon] = ACTIONS(131),
    [anon_sym_log] = ACTIONS(131),
    [anon_sym_retries] = ACTIONS(131),
    [anon_sym_cookie] = ACTIONS(131),
    [anon_sym_errorfile] = ACTIONS(131),
    [anon_sym_default_backend] = ACTIONS(131),
    [anon_sym_use_backend] = ACTIONS(131),
    [anon_sym_compression] = ACTIONS(131),
    [anon_sym_redirect] = ACTIONS(131),
    [anon_sym_source] = ACTIONS(131),
    [anon_sym_id] = ACTIONS(131),
    [anon_sym_disabled] = ACTIONS(131),
    [anon_sym_enabled] = ACTIONS(131),
    [anon_sym_dispatch] = ACTIONS(131),
    [anon_sym_backlog] = ACTIONS(131),
    [anon_sym_description] = ACTIONS(131),
    [anon_sym_chroot] = ACTIONS(131),
    [anon_sym_ca_DASHbase] = ACTIONS(131),
    [anon_sym_crt_DASHbase] = ACTIONS(131),
    [anon_sym_nbproc] = ACTIONS(131),
    [anon_sym_cpu_DASHmap] = ACTIONS(131),
    [anon_sym_lua_DASHload] = ACTIONS(131),
    [anon_sym_monitor_DASHnet] = ACTIONS(131),
    [anon_sym_monitor_DASHuri] = ACTIONS(131),
    [anon_sym_grace] = ACTIONS(131),
    [anon_sym_hash_DASHtype] = ACTIONS(131),
    [anon_sym_force_DASHpersist] = ACTIONS(131),
    [anon_sym_ignore_DASHpersist] = ACTIONS(131),
    [anon_sym_bind_DASHprocess] = ACTIONS(131),
    [anon_sym_default_DASHserver] = ACTIONS(131),
    [anon_sym_log_DASHformat] = ACTIONS(131),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(131),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(131),
    [anon_sym_nameserver] = ACTIONS(131),
    [anon_sym_peer] = ACTIONS(131),
    [anon_sym_resolution_pool_size] = ACTIONS(131),
    [anon_sym_resolve_retries] = ACTIONS(131),
    [anon_sym_reqadd] = ACTIONS(131),
    [anon_sym_reqallow] = ACTIONS(131),
    [anon_sym_reqdel] = ACTIONS(131),
    [anon_sym_reqdeny] = ACTIONS(131),
    [anon_sym_reqiallow] = ACTIONS(131),
    [anon_sym_reqidel] = ACTIONS(131),
    [anon_sym_reqideny] = ACTIONS(131),
    [anon_sym_reqipass] = ACTIONS(131),
    [anon_sym_reqirep] = ACTIONS(131),
    [anon_sym_reqisetbe] = ACTIONS(131),
    [anon_sym_reqitarpit] = ACTIONS(131),
    [anon_sym_reqpass] = ACTIONS(131),
    [anon_sym_reqrep] = ACTIONS(131),
    [anon_sym_reqsetbe] = ACTIONS(131),
    [anon_sym_reqtarpit] = ACTIONS(131),
    [anon_sym_rspadd] = ACTIONS(131),
    [anon_sym_rspdel] = ACTIONS(131),
    [anon_sym_rspdeny] = ACTIONS(131),
    [anon_sym_rspidel] = ACTIONS(131),
    [anon_sym_rspideny] = ACTIONS(131),
    [anon_sym_rspirep] = ACTIONS(131),
    [anon_sym_rsprep] = ACTIONS(131),
    [anon_sym_option] = ACTIONS(131),
    [anon_sym_timeout] = ACTIONS(131),
    [anon_sym_stats] = ACTIONS(131),
    [anon_sym_http_DASHrequest] = ACTIONS(131),
    [anon_sym_http_DASHresponse] = ACTIONS(131),
    [anon_sym_http_DASHcheck] = ACTIONS(131),
    [anon_sym_tcp_DASHrequest] = ACTIONS(131),
    [anon_sym_tcp_DASHresponse] = ACTIONS(131),
    [anon_sym_stick] = ACTIONS(131),
    [anon_sym_stick_DASHtable] = ACTIONS(131),
    [anon_sym_capture] = ACTIONS(131),
    [anon_sym_use_DASHserver] = ACTIONS(131),
    [anon_sym_monitor] = ACTIONS(131),
    [anon_sym_rate_DASHlimit] = ACTIONS(131),
    [anon_sym_persist] = ACTIONS(131),
    [sym_string] = ACTIONS(129),
    [sym_ip_address] = ACTIONS(129),
    [sym_wildcard_bind] = ACTIONS(129),
    [sym_number] = ACTIONS(131),
    [sym_time_value] = ACTIONS(129),
    [sym_parameter] = ACTIONS(129),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(129),
    [anon_sym_BANG] = ACTIONS(129),
    [anon_sym_if] = ACTIONS(131),
    [anon_sym_unless] = ACTIONS(131),
    [anon_sym_rewrite] = ACTIONS(131),
    [sym_identifier] = ACTIONS(131),
    [sym_path] = ACTIONS(129),
  },
  [15] = {
    [ts_builtin_sym_end] = ACTIONS(133),
    [sym_comment] = ACTIONS(133),
    [anon_sym_global] = ACTIONS(135),
    [anon_sym_defaults] = ACTIONS(135),
    [anon_sym_frontend] = ACTIONS(135),
    [anon_sym_backend] = ACTIONS(135),
    [anon_sym_listen] = ACTIONS(135),
    [anon_sym_peers] = ACTIONS(135),
    [anon_sym_resolvers] = ACTIONS(135),
    [anon_sym_userlist] = ACTIONS(135),
    [anon_sym_aggregations] = ACTIONS(135),
    [anon_sym_acl] = ACTIONS(135),
    [anon_sym_bind] = ACTIONS(135),
    [anon_sym_server] = ACTIONS(135),
    [anon_sym_balance] = ACTIONS(135),
    [anon_sym_mode] = ACTIONS(135),
    [anon_sym_maxconn] = ACTIONS(135),
    [anon_sym_user] = ACTIONS(135),
    [anon_sym_group] = ACTIONS(135),
    [anon_sym_daemon] = ACTIONS(135),
    [anon_sym_log] = ACTIONS(135),
    [anon_sym_retries] = ACTIONS(135),
    [anon_sym_cookie] = ACTIONS(135),
    [anon_sym_errorfile] = ACTIONS(135),
    [anon_sym_default_backend] = ACTIONS(135),
    [anon_sym_use_backend] = ACTIONS(135),
    [anon_sym_compression] = ACTIONS(135),
    [anon_sym_redirect] = ACTIONS(135),
    [anon_sym_source] = ACTIONS(135),
    [anon_sym_id] = ACTIONS(135),
    [anon_sym_disabled] = ACTIONS(135),
    [anon_sym_enabled] = ACTIONS(135),
    [anon_sym_dispatch] = ACTIONS(135),
    [anon_sym_backlog] = ACTIONS(135),
    [anon_sym_description] = ACTIONS(135),
    [anon_sym_chroot] = ACTIONS(135),
    [anon_sym_ca_DASHbase] = ACTIONS(135),
    [anon_sym_crt_DASHbase] = ACTIONS(135),
    [anon_sym_nbproc] = ACTIONS(135),
    [anon_sym_cpu_DASHmap] = ACTIONS(135),
    [anon_sym_lua_DASHload] = ACTIONS(135),
    [anon_sym_monitor_DASHnet] = ACTIONS(135),
    [anon_sym_monitor_DASHuri] = ACTIONS(135),
    [anon_sym_grace] = ACTIONS(135),
    [anon_sym_hash_DASHtype] = ACTIONS(135),
    [anon_sym_force_DASHpersist] = ACTIONS(135),
    [anon_sym_ignore_DASHpersist] = ACTIONS(135),
    [anon_sym_bind_DASHprocess] = ACTIONS(135),
    [anon_sym_default_DASHserver] = ACTIONS(135),
    [anon_sym_log_DASHformat] = ACTIONS(135),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(135),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(135),
    [anon_sym_nameserver] = ACTIONS(135),
    [anon_sym_peer] = ACTIONS(135),
    [anon_sym_resolution_pool_size] = ACTIONS(135),
    [anon_sym_resolve_retries] = ACTIONS(135),
    [anon_sym_reqadd] = ACTIONS(135),
    [anon_sym_reqallow] = ACTIONS(135),
    [anon_sym_reqdel] = ACTIONS(135),
    [anon_sym_reqdeny] = ACTIONS(135),
    [anon_sym_reqiallow] = ACTIONS(135),
    [anon_sym_reqidel] = ACTIONS(135),
    [anon_sym_reqideny] = ACTIONS(135),
    [anon_sym_reqipass] = ACTIONS(135),
    [anon_sym_reqirep] = ACTIONS(135),
    [anon_sym_reqisetbe] = ACTIONS(135),
    [anon_sym_reqitarpit] = ACTIONS(135),
    [anon_sym_reqpass] = ACTIONS(135),
    [anon_sym_reqrep] = ACTIONS(135),
    [anon_sym_reqsetbe] = ACTIONS(135),
    [anon_sym_reqtarpit] = ACTIONS(135),
    [anon_sym_rspadd] = ACTIONS(135),
    [anon_sym_rspdel] = ACTIONS(135),
    [anon_sym_rspdeny] = ACTIONS(135),
    [anon_sym_rspidel] = ACTIONS(135),
    [anon_sym_rspideny] = ACTIONS(135),
    [anon_sym_rspirep] = ACTIONS(135),
    [anon_sym_rsprep] = ACTIONS(135),
    [anon_sym_option] = ACTIONS(135),
    [anon_sym_timeout] = ACTIONS(135),
    [anon_sym_stats] = ACTIONS(135),
    [anon_sym_http_DASHrequest] = ACTIONS(135),
    [anon_sym_http_DASHresponse] = ACTIONS(135),
    [anon_sym_http_DASHcheck] = ACTIONS(135),
    [anon_sym_tcp_DASHrequest] = ACTIONS(135),
    [anon_sym_tcp_DASHresponse] = ACTIONS(135),
    [anon_sym_stick] = ACTIONS(135),
    [anon_sym_stick_DASHtable] = ACTIONS(135),
    [anon_sym_capture] = ACTIONS(135),
    [anon_sym_use_DASHserver] = ACTIONS(135),
    [anon_sym_monitor] = ACTIONS(135),
    [anon_sym_rate_DASHlimit] = ACTIONS(135),
    [anon_sym_persist] = ACTIONS(135),
    [sym_string] = ACTIONS(133),
    [sym_ip_address] = ACTIONS(133),
    [sym_wildcard_bind] = ACTIONS(133),
    [sym_number] = ACTIONS(135),
    [sym_time_value] = ACTIONS(133),
    [sym_parameter] = ACTIONS(133),
    [anon_sym_or] = ACTIONS(135),
    [anon_sym_PIPE_PIPE] = ACTIONS(133),
    [anon_sym_BANG] = ACTIONS(133),
    [anon_sym_if] = ACTIONS(135),
    [anon_sym_unless] = ACTIONS(135),
    [anon_sym_rewrite] = ACTIONS(135),
    [sym_identifier] = ACTIONS(135),
    [sym_path] = ACTIONS(133),
  },
  [16] = {
    [ts_builtin_sym_end] = ACTIONS(137),
    [sym_comment] = ACTIONS(137),
    [anon_sym_global] = ACTIONS(139),
    [anon_sym_defaults] = ACTIONS(139),
    [anon_sym_frontend] = ACTIONS(139),
    [anon_sym_backend] = ACTIONS(139),
    [anon_sym_listen] = ACTIONS(139),
    [anon_sym_peers] = ACTIONS(139),
    [anon_sym_resolvers] = ACTIONS(139),
    [anon_sym_userlist] = ACTIONS(139),
    [anon_sym_aggregations] = ACTIONS(139),
    [anon_sym_acl] = ACTIONS(139),
    [anon_sym_bind] = ACTIONS(139),
    [anon_sym_server] = ACTIONS(139),
    [anon_sym_balance] = ACTIONS(139),
    [anon_sym_mode] = ACTIONS(139),
    [anon_sym_maxconn] = ACTIONS(139),
    [anon_sym_user] = ACTIONS(139),
    [anon_sym_group] = ACTIONS(139),
    [anon_sym_daemon] = ACTIONS(139),
    [anon_sym_log] = ACTIONS(139),
    [anon_sym_retries] = ACTIONS(139),
    [anon_sym_cookie] = ACTIONS(139),
    [anon_sym_errorfile] = ACTIONS(139),
    [anon_sym_default_backend] = ACTIONS(139),
    [anon_sym_use_backend] = ACTIONS(139),
    [anon_sym_compression] = ACTIONS(139),
    [anon_sym_redirect] = ACTIONS(139),
    [anon_sym_source] = ACTIONS(139),
    [anon_sym_id] = ACTIONS(139),
    [anon_sym_disabled] = ACTIONS(139),
    [anon_sym_enabled] = ACTIONS(139),
    [anon_sym_dispatch] = ACTIONS(139),
    [anon_sym_backlog] = ACTIONS(139),
    [anon_sym_description] = ACTIONS(139),
    [anon_sym_chroot] = ACTIONS(139),
    [anon_sym_ca_DASHbase] = ACTIONS(139),
    [anon_sym_crt_DASHbase] = ACTIONS(139),
    [anon_sym_nbproc] = ACTIONS(139),
    [anon_sym_cpu_DASHmap] = ACTIONS(139),
    [anon_sym_lua_DASHload] = ACTIONS(139),
    [anon_sym_monitor_DASHnet] = ACTIONS(139),
    [anon_sym_monitor_DASHuri] = ACTIONS(139),
    [anon_sym_grace] = ACTIONS(139),
    [anon_sym_hash_DASHtype] = ACTIONS(139),
    [anon_sym_force_DASHpersist] = ACTIONS(139),
    [anon_sym_ignore_DASHpersist] = ACTIONS(139),
    [anon_sym_bind_DASHprocess] = ACTIONS(139),
    [anon_sym_default_DASHserver] = ACTIONS(139),
    [anon_sym_log_DASHformat] = ACTIONS(139),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(139),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(139),
    [anon_sym_nameserver] = ACTIONS(139),
    [anon_sym_peer] = ACTIONS(139),
    [anon_sym_resolution_pool_size] = ACTIONS(139),
    [anon_sym_resolve_retries] = ACTIONS(139),
    [anon_sym_reqadd] = ACTIONS(139),
    [anon_sym_reqallow] = ACTIONS(139),
    [anon_sym_reqdel] = ACTIONS(139),
    [anon_sym_reqdeny] = ACTIONS(139),
    [anon_sym_reqiallow] = ACTIONS(139),
    [anon_sym_reqidel] = ACTIONS(139),
    [anon_sym_reqideny] = ACTIONS(139),
    [anon_sym_reqipass] = ACTIONS(139),
    [anon_sym_reqirep] = ACTIONS(139),
    [anon_sym_reqisetbe] = ACTIONS(139),
    [anon_sym_reqitarpit] = ACTIONS(139),
    [anon_sym_reqpass] = ACTIONS(139),
    [anon_sym_reqrep] = ACTIONS(139),
    [anon_sym_reqsetbe] = ACTIONS(139),
    [anon_sym_reqtarpit] = ACTIONS(139),
    [anon_sym_rspadd] = ACTIONS(139),
    [anon_sym_rspdel] = ACTIONS(139),
    [anon_sym_rspdeny] = ACTIONS(139),
    [anon_sym_rspidel] = ACTIONS(139),
    [anon_sym_rspideny] = ACTIONS(139),
    [anon_sym_rspirep] = ACTIONS(139),
    [anon_sym_rsprep] = ACTIONS(139),
    [anon_sym_option] = ACTIONS(139),
    [anon_sym_timeout] = ACTIONS(139),
    [anon_sym_stats] = ACTIONS(139),
    [anon_sym_http_DASHrequest] = ACTIONS(139),
    [anon_sym_http_DASHresponse] = ACTIONS(139),
    [anon_sym_http_DASHcheck] = ACTIONS(139),
    [anon_sym_tcp_DASHrequest] = ACTIONS(139),
    [anon_sym_tcp_DASHresponse] = ACTIONS(139),
    [anon_sym_stick] = ACTIONS(139),
    [anon_sym_stick_DASHtable] = ACTIONS(139),
    [anon_sym_capture] = ACTIONS(139),
    [anon_sym_use_DASHserver] = ACTIONS(139),
    [anon_sym_monitor] = ACTIONS(139),
    [anon_sym_rate_DASHlimit] = ACTIONS(139),
    [anon_sym_persist] = ACTIONS(139),
    [sym_string] = ACTIONS(137),
    [sym_ip_address] = ACTIONS(137),
    [sym_wildcard_bind] = ACTIONS(137),
    [sym_number] = ACTIONS(139),
    [sym_time_value] = ACTIONS(137),
    [sym_parameter] = ACTIONS(137),
    [anon_sym_or] = ACTIONS(139),
    [anon_sym_PIPE_PIPE] = ACTIONS(137),
    [anon_sym_BANG] = ACTIONS(137),
    [anon_sym_if] = ACTIONS(139),
    [anon_sym_unless] = ACTIONS(139),
    [anon_sym_rewrite] = ACTIONS(139),
    [sym_identifier] = ACTIONS(139),
    [sym_path] = ACTIONS(137),
  },
  [17] = {
    [ts_builtin_sym_end] = ACTIONS(141),
    [sym_comment] = ACTIONS(141),
    [anon_sym_global] = ACTIONS(143),
    [anon_sym_defaults] = ACTIONS(143),
    [anon_sym_frontend] = ACTIONS(143),
    [anon_sym_backend] = ACTIONS(143),
    [anon_sym_listen] = ACTIONS(143),
    [anon_sym_peers] = ACTIONS(143),
    [anon_sym_resolvers] = ACTIONS(143),
    [anon_sym_userlist] = ACTIONS(143),
    [anon_sym_aggregations] = ACTIONS(143),
    [anon_sym_acl] = ACTIONS(143),
    [anon_sym_bind] = ACTIONS(143),
    [anon_sym_server] = ACTIONS(143),
    [anon_sym_balance] = ACTIONS(143),
    [anon_sym_mode] = ACTIONS(143),
    [anon_sym_maxconn] = ACTIONS(143),
    [anon_sym_user] = ACTIONS(143),
    [anon_sym_group] = ACTIONS(143),
    [anon_sym_daemon] = ACTIONS(143),
    [anon_sym_log] = ACTIONS(143),
    [anon_sym_retries] = ACTIONS(143),
    [anon_sym_cookie] = ACTIONS(143),
    [anon_sym_errorfile] = ACTIONS(143),
    [anon_sym_default_backend] = ACTIONS(143),
    [anon_sym_use_backend] = ACTIONS(143),
    [anon_sym_compression] = ACTIONS(143),
    [anon_sym_redirect] = ACTIONS(143),
    [anon_sym_source] = ACTIONS(143),
    [anon_sym_id] = ACTIONS(143),
    [anon_sym_disabled] = ACTIONS(143),
    [anon_sym_enabled] = ACTIONS(143),
    [anon_sym_dispatch] = ACTIONS(143),
    [anon_sym_backlog] = ACTIONS(143),
    [anon_sym_description] = ACTIONS(143),
    [anon_sym_chroot] = ACTIONS(143),
    [anon_sym_ca_DASHbase] = ACTIONS(143),
    [anon_sym_crt_DASHbase] = ACTIONS(143),
    [anon_sym_nbproc] = ACTIONS(143),
    [anon_sym_cpu_DASHmap] = ACTIONS(143),
    [anon_sym_lua_DASHload] = ACTIONS(143),
    [anon_sym_monitor_DASHnet] = ACTIONS(143),
    [anon_sym_monitor_DASHuri] = ACTIONS(143),
    [anon_sym_grace] = ACTIONS(143),
    [anon_sym_hash_DASHtype] = ACTIONS(143),
    [anon_sym_force_DASHpersist] = ACTIONS(143),
    [anon_sym_ignore_DASHpersist] = ACTIONS(143),
    [anon_sym_bind_DASHprocess] = ACTIONS(143),
    [anon_sym_default_DASHserver] = ACTIONS(143),
    [anon_sym_log_DASHformat] = ACTIONS(143),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(143),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(143),
    [anon_sym_nameserver] = ACTIONS(143),
    [anon_sym_peer] = ACTIONS(143),
    [anon_sym_resolution_pool_size] = ACTIONS(143),
    [anon_sym_resolve_retries] = ACTIONS(143),
    [anon_sym_reqadd] = ACTIONS(143),
    [anon_sym_reqallow] = ACTIONS(143),
    [anon_sym_reqdel] = ACTIONS(143),
    [anon_sym_reqdeny] = ACTIONS(143),
    [anon_sym_reqiallow] = ACTIONS(143),
    [anon_sym_reqidel] = ACTIONS(143),
    [anon_sym_reqideny] = ACTIONS(143),
    [anon_sym_reqipass] = ACTIONS(143),
    [anon_sym_reqirep] = ACTIONS(143),
    [anon_sym_reqisetbe] = ACTIONS(143),
    [anon_sym_reqitarpit] = ACTIONS(143),
    [anon_sym_reqpass] = ACTIONS(143),
    [anon_sym_reqrep] = ACTIONS(143),
    [anon_sym_reqsetbe] = ACTIONS(143),
    [anon_sym_reqtarpit] = ACTIONS(143),
    [anon_sym_rspadd] = ACTIONS(143),
    [anon_sym_rspdel] = ACTIONS(143),
    [anon_sym_rspdeny] = ACTIONS(143),
    [anon_sym_rspidel] = ACTIONS(143),
    [anon_sym_rspideny] = ACTIONS(143),
    [anon_sym_rspirep] = ACTIONS(143),
    [anon_sym_rsprep] = ACTIONS(143),
    [anon_sym_option] = ACTIONS(143),
    [anon_sym_timeout] = ACTIONS(143),
    [anon_sym_stats] = ACTIONS(143),
    [anon_sym_http_DASHrequest] = ACTIONS(143),
    [anon_sym_http_DASHresponse] = ACTIONS(143),
    [anon_sym_http_DASHcheck] = ACTIONS(143),
    [anon_sym_tcp_DASHrequest] = ACTIONS(143),
    [anon_sym_tcp_DASHresponse] = ACTIONS(143),
    [anon_sym_stick] = ACTIONS(143),
    [anon_sym_stick_DASHtable] = ACTIONS(143),
    [anon_sym_capture] = ACTIONS(143),
    [anon_sym_use_DASHserver] = ACTIONS(143),
    [anon_sym_monitor] = ACTIONS(143),
    [anon_sym_rate_DASHlimit] = ACTIONS(143),
    [anon_sym_persist] = ACTIONS(143),
    [sym_string] = ACTIONS(141),
    [sym_ip_address] = ACTIONS(141),
    [sym_wildcard_bind] = ACTIONS(141),
    [sym_number] = ACTIONS(143),
    [sym_time_value] = ACTIONS(141),
    [sym_parameter] = ACTIONS(141),
    [anon_sym_or] = ACTIONS(143),
    [anon_sym_PIPE_PIPE] = ACTIONS(141),
    [anon_sym_BANG] = ACTIONS(141),
    [anon_sym_if] = ACTIONS(143),
    [anon_sym_unless] = ACTIONS(143),
    [anon_sym_rewrite] = ACTIONS(143),
    [sym_identifier] = ACTIONS(143),
    [sym_path] = ACTIONS(141),
  },
  [18] = {
    [ts_builtin_sym_end] = ACTIONS(145),
    [sym_comment] = ACTIONS(145),
    [anon_sym_global] = ACTIONS(147),
    [anon_sym_defaults] = ACTIONS(147),
    [anon_sym_frontend] = ACTIONS(147),
    [anon_sym_backend] = ACTIONS(147),
    [anon_sym_listen] = ACTIONS(147),
    [anon_sym_peers] = ACTIONS(147),
    [anon_sym_resolvers] = ACTIONS(147),
    [anon_sym_userlist] = ACTIONS(147),
    [anon_sym_aggregations] = ACTIONS(147),
    [anon_sym_acl] = ACTIONS(147),
    [anon_sym_bind] = ACTIONS(147),
    [anon_sym_server] = ACTIONS(147),
    [anon_sym_balance] = ACTIONS(147),
    [anon_sym_mode] = ACTIONS(147),
    [anon_sym_maxconn] = ACTIONS(147),
    [anon_sym_user] = ACTIONS(147),
    [anon_sym_group] = ACTIONS(147),
    [anon_sym_daemon] = ACTIONS(147),
    [anon_sym_log] = ACTIONS(147),
    [anon_sym_retries] = ACTIONS(147),
    [anon_sym_cookie] = ACTIONS(147),
    [anon_sym_errorfile] = ACTIONS(147),
    [anon_sym_default_backend] = ACTIONS(147),
    [anon_sym_use_backend] = ACTIONS(147),
    [anon_sym_compression] = ACTIONS(147),
    [anon_sym_redirect] = ACTIONS(147),
    [anon_sym_source] = ACTIONS(147),
    [anon_sym_id] = ACTIONS(147),
    [anon_sym_disabled] = ACTIONS(147),
    [anon_sym_enabled] = ACTIONS(147),
    [anon_sym_dispatch] = ACTIONS(147),
    [anon_sym_backlog] = ACTIONS(147),
    [anon_sym_description] = ACTIONS(147),
    [anon_sym_chroot] = ACTIONS(147),
    [anon_sym_ca_DASHbase] = ACTIONS(147),
    [anon_sym_crt_DASHbase] = ACTIONS(147),
    [anon_sym_nbproc] = ACTIONS(147),
    [anon_sym_cpu_DASHmap] = ACTIONS(147),
    [anon_sym_lua_DASHload] = ACTIONS(147),
    [anon_sym_monitor_DASHnet] = ACTIONS(147),
    [anon_sym_monitor_DASHuri] = ACTIONS(147),
    [anon_sym_grace] = ACTIONS(147),
    [anon_sym_hash_DASHtype] = ACTIONS(147),
    [anon_sym_force_DASHpersist] = ACTIONS(147),
    [anon_sym_ignore_DASHpersist] = ACTIONS(147),
    [anon_sym_bind_DASHprocess] = ACTIONS(147),
    [anon_sym_default_DASHserver] = ACTIONS(147),
    [anon_sym_log_DASHformat] = ACTIONS(147),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(147),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(147),
    [anon_sym_nameserver] = ACTIONS(147),
    [anon_sym_peer] = ACTIONS(147),
    [anon_sym_resolution_pool_size] = ACTIONS(147),
    [anon_sym_resolve_retries] = ACTIONS(147),
    [anon_sym_reqadd] = ACTIONS(147),
    [anon_sym_reqallow] = ACTIONS(147),
    [anon_sym_reqdel] = ACTIONS(147),
    [anon_sym_reqdeny] = ACTIONS(147),
    [anon_sym_reqiallow] = ACTIONS(147),
    [anon_sym_reqidel] = ACTIONS(147),
    [anon_sym_reqideny] = ACTIONS(147),
    [anon_sym_reqipass] = ACTIONS(147),
    [anon_sym_reqirep] = ACTIONS(147),
    [anon_sym_reqisetbe] = ACTIONS(147),
    [anon_sym_reqitarpit] = ACTIONS(147),
    [anon_sym_reqpass] = ACTIONS(147),
    [anon_sym_reqrep] = ACTIONS(147),
    [anon_sym_reqsetbe] = ACTIONS(147),
    [anon_sym_reqtarpit] = ACTIONS(147),
    [anon_sym_rspadd] = ACTIONS(147),
    [anon_sym_rspdel] = ACTIONS(147),
    [anon_sym_rspdeny] = ACTIONS(147),
    [anon_sym_rspidel] = ACTIONS(147),
    [anon_sym_rspideny] = ACTIONS(147),
    [anon_sym_rspirep] = ACTIONS(147),
    [anon_sym_rsprep] = ACTIONS(147),
    [anon_sym_option] = ACTIONS(147),
    [anon_sym_timeout] = ACTIONS(147),
    [anon_sym_stats] = ACTIONS(147),
    [anon_sym_http_DASHrequest] = ACTIONS(147),
    [anon_sym_http_DASHresponse] = ACTIONS(147),
    [anon_sym_http_DASHcheck] = ACTIONS(147),
    [anon_sym_tcp_DASHrequest] = ACTIONS(147),
    [anon_sym_tcp_DASHresponse] = ACTIONS(147),
    [anon_sym_stick] = ACTIONS(147),
    [anon_sym_stick_DASHtable] = ACTIONS(147),
    [anon_sym_capture] = ACTIONS(147),
    [anon_sym_use_DASHserver] = ACTIONS(147),
    [anon_sym_monitor] = ACTIONS(147),
    [anon_sym_rate_DASHlimit] = ACTIONS(147),
    [anon_sym_persist] = ACTIONS(147),
    [sym_string] = ACTIONS(145),
    [sym_ip_address] = ACTIONS(145),
    [sym_wildcard_bind] = ACTIONS(145),
    [sym_number] = ACTIONS(147),
    [sym_time_value] = ACTIONS(145),
    [sym_parameter] = ACTIONS(145),
    [anon_sym_or] = ACTIONS(147),
    [anon_sym_PIPE_PIPE] = ACTIONS(145),
    [anon_sym_BANG] = ACTIONS(145),
    [anon_sym_if] = ACTIONS(147),
    [anon_sym_unless] = ACTIONS(147),
    [anon_sym_rewrite] = ACTIONS(147),
    [sym_identifier] = ACTIONS(147),
    [sym_path] = ACTIONS(145),
  },
  [19] = {
    [ts_builtin_sym_end] = ACTIONS(149),
    [sym_comment] = ACTIONS(149),
    [anon_sym_global] = ACTIONS(151),
    [anon_sym_defaults] = ACTIONS(151),
    [anon_sym_frontend] = ACTIONS(151),
    [anon_sym_backend] = ACTIONS(151),
    [anon_sym_listen] = ACTIONS(151),
    [anon_sym_peers] = ACTIONS(151),
    [anon_sym_resolvers] = ACTIONS(151),
    [anon_sym_userlist] = ACTIONS(151),
    [anon_sym_aggregations] = ACTIONS(151),
    [anon_sym_acl] = ACTIONS(151),
    [anon_sym_bind] = ACTIONS(151),
    [anon_sym_server] = ACTIONS(151),
    [anon_sym_balance] = ACTIONS(151),
    [anon_sym_mode] = ACTIONS(151),
    [anon_sym_maxconn] = ACTIONS(151),
    [anon_sym_user] = ACTIONS(151),
    [anon_sym_group] = ACTIONS(151),
    [anon_sym_daemon] = ACTIONS(151),
    [anon_sym_log] = ACTIONS(151),
    [anon_sym_retries] = ACTIONS(151),
    [anon_sym_cookie] = ACTIONS(151),
    [anon_sym_errorfile] = ACTIONS(151),
    [anon_sym_default_backend] = ACTIONS(151),
    [anon_sym_use_backend] = ACTIONS(151),
    [anon_sym_compression] = ACTIONS(151),
    [anon_sym_redirect] = ACTIONS(151),
    [anon_sym_source] = ACTIONS(151),
    [anon_sym_id] = ACTIONS(151),
    [anon_sym_disabled] = ACTIONS(151),
    [anon_sym_enabled] = ACTIONS(151),
    [anon_sym_dispatch] = ACTIONS(151),
    [anon_sym_backlog] = ACTIONS(151),
    [anon_sym_description] = ACTIONS(151),
    [anon_sym_chroot] = ACTIONS(151),
    [anon_sym_ca_DASHbase] = ACTIONS(151),
    [anon_sym_crt_DASHbase] = ACTIONS(151),
    [anon_sym_nbproc] = ACTIONS(151),
    [anon_sym_cpu_DASHmap] = ACTIONS(151),
    [anon_sym_lua_DASHload] = ACTIONS(151),
    [anon_sym_monitor_DASHnet] = ACTIONS(151),
    [anon_sym_monitor_DASHuri] = ACTIONS(151),
    [anon_sym_grace] = ACTIONS(151),
    [anon_sym_hash_DASHtype] = ACTIONS(151),
    [anon_sym_force_DASHpersist] = ACTIONS(151),
    [anon_sym_ignore_DASHpersist] = ACTIONS(151),
    [anon_sym_bind_DASHprocess] = ACTIONS(151),
    [anon_sym_default_DASHserver] = ACTIONS(151),
    [anon_sym_log_DASHformat] = ACTIONS(151),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(151),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(151),
    [anon_sym_nameserver] = ACTIONS(151),
    [anon_sym_peer] = ACTIONS(151),
    [anon_sym_resolution_pool_size] = ACTIONS(151),
    [anon_sym_resolve_retries] = ACTIONS(151),
    [anon_sym_reqadd] = ACTIONS(151),
    [anon_sym_reqallow] = ACTIONS(151),
    [anon_sym_reqdel] = ACTIONS(151),
    [anon_sym_reqdeny] = ACTIONS(151),
    [anon_sym_reqiallow] = ACTIONS(151),
    [anon_sym_reqidel] = ACTIONS(151),
    [anon_sym_reqideny] = ACTIONS(151),
    [anon_sym_reqipass] = ACTIONS(151),
    [anon_sym_reqirep] = ACTIONS(151),
    [anon_sym_reqisetbe] = ACTIONS(151),
    [anon_sym_reqitarpit] = ACTIONS(151),
    [anon_sym_reqpass] = ACTIONS(151),
    [anon_sym_reqrep] = ACTIONS(151),
    [anon_sym_reqsetbe] = ACTIONS(151),
    [anon_sym_reqtarpit] = ACTIONS(151),
    [anon_sym_rspadd] = ACTIONS(151),
    [anon_sym_rspdel] = ACTIONS(151),
    [anon_sym_rspdeny] = ACTIONS(151),
    [anon_sym_rspidel] = ACTIONS(151),
    [anon_sym_rspideny] = ACTIONS(151),
    [anon_sym_rspirep] = ACTIONS(151),
    [anon_sym_rsprep] = ACTIONS(151),
    [anon_sym_option] = ACTIONS(151),
    [anon_sym_timeout] = ACTIONS(151),
    [anon_sym_stats] = ACTIONS(151),
    [anon_sym_http_DASHrequest] = ACTIONS(151),
    [anon_sym_http_DASHresponse] = ACTIONS(151),
    [anon_sym_http_DASHcheck] = ACTIONS(151),
    [anon_sym_tcp_DASHrequest] = ACTIONS(151),
    [anon_sym_tcp_DASHresponse] = ACTIONS(151),
    [anon_sym_stick] = ACTIONS(151),
    [anon_sym_stick_DASHtable] = ACTIONS(151),
    [anon_sym_capture] = ACTIONS(151),
    [anon_sym_use_DASHserver] = ACTIONS(151),
    [anon_sym_monitor] = ACTIONS(151),
    [anon_sym_rate_DASHlimit] = ACTIONS(151),
    [anon_sym_persist] = ACTIONS(151),
    [sym_string] = ACTIONS(149),
    [sym_ip_address] = ACTIONS(149),
    [sym_wildcard_bind] = ACTIONS(149),
    [sym_number] = ACTIONS(151),
    [sym_time_value] = ACTIONS(149),
    [sym_parameter] = ACTIONS(149),
    [anon_sym_or] = ACTIONS(151),
    [anon_sym_PIPE_PIPE] = ACTIONS(149),
    [anon_sym_BANG] = ACTIONS(149),
    [anon_sym_if] = ACTIONS(151),
    [anon_sym_unless] = ACTIONS(151),
    [anon_sym_rewrite] = ACTIONS(151),
    [sym_identifier] = ACTIONS(151),
    [sym_path] = ACTIONS(149),
  },
  [20] = {
    [sym__statement] = STATE(20),
    [sym_section] = STATE(20),
    [sym_section_name] = STATE(22),
    [sym_directive] = STATE(20),
    [sym_keyword] = STATE(2),
    [sym_keyword_combination] = STATE(2),
    [aux_sym_source_file_repeat1] = STATE(20),
    [ts_builtin_sym_end] = ACTIONS(153),
    [sym_comment] = ACTIONS(155),
    [anon_sym_global] = ACTIONS(158),
    [anon_sym_defaults] = ACTIONS(158),
    [anon_sym_frontend] = ACTIONS(158),
    [anon_sym_backend] = ACTIONS(158),
    [anon_sym_listen] = ACTIONS(158),
    [anon_sym_peers] = ACTIONS(158),
    [anon_sym_resolvers] = ACTIONS(158),
    [anon_sym_userlist] = ACTIONS(158),
    [anon_sym_aggregations] = ACTIONS(158),
    [anon_sym_acl] = ACTIONS(161),
    [anon_sym_bind] = ACTIONS(164),
    [anon_sym_server] = ACTIONS(161),
    [anon_sym_balance] = ACTIONS(161),
    [anon_sym_mode] = ACTIONS(161),
    [anon_sym_maxconn] = ACTIONS(161),
    [anon_sym_user] = ACTIONS(164),
    [anon_sym_group] = ACTIONS(161),
    [anon_sym_daemon] = ACTIONS(161),
    [anon_sym_log] = ACTIONS(164),
    [anon_sym_retries] = ACTIONS(161),
    [anon_sym_cookie] = ACTIONS(161),
    [anon_sym_errorfile] = ACTIONS(161),
    [anon_sym_default_backend] = ACTIONS(161),
    [anon_sym_use_backend] = ACTIONS(161),
    [anon_sym_compression] = ACTIONS(161),
    [anon_sym_redirect] = ACTIONS(161),
    [anon_sym_source] = ACTIONS(161),
    [anon_sym_id] = ACTIONS(161),
    [anon_sym_disabled] = ACTIONS(161),
    [anon_sym_enabled] = ACTIONS(161),
    [anon_sym_dispatch] = ACTIONS(161),
    [anon_sym_backlog] = ACTIONS(161),
    [anon_sym_description] = ACTIONS(161),
    [anon_sym_chroot] = ACTIONS(161),
    [anon_sym_ca_DASHbase] = ACTIONS(161),
    [anon_sym_crt_DASHbase] = ACTIONS(161),
    [anon_sym_nbproc] = ACTIONS(161),
    [anon_sym_cpu_DASHmap] = ACTIONS(161),
    [anon_sym_lua_DASHload] = ACTIONS(161),
    [anon_sym_monitor_DASHnet] = ACTIONS(161),
    [anon_sym_monitor_DASHuri] = ACTIONS(161),
    [anon_sym_grace] = ACTIONS(161),
    [anon_sym_hash_DASHtype] = ACTIONS(161),
    [anon_sym_force_DASHpersist] = ACTIONS(161),
    [anon_sym_ignore_DASHpersist] = ACTIONS(161),
    [anon_sym_bind_DASHprocess] = ACTIONS(161),
    [anon_sym_default_DASHserver] = ACTIONS(161),
    [anon_sym_log_DASHformat] = ACTIONS(161),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(161),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(161),
    [anon_sym_nameserver] = ACTIONS(161),
    [anon_sym_peer] = ACTIONS(164),
    [anon_sym_resolution_pool_size] = ACTIONS(161),
    [anon_sym_resolve_retries] = ACTIONS(161),
    [anon_sym_reqadd] = ACTIONS(161),
    [anon_sym_reqallow] = ACTIONS(161),
    [anon_sym_reqdel] = ACTIONS(161),
    [anon_sym_reqdeny] = ACTIONS(161),
    [anon_sym_reqiallow] = ACTIONS(161),
    [anon_sym_reqidel] = ACTIONS(161),
    [anon_sym_reqideny] = ACTIONS(161),
    [anon_sym_reqipass] = ACTIONS(161),
    [anon_sym_reqirep] = ACTIONS(161),
    [anon_sym_reqisetbe] = ACTIONS(161),
    [anon_sym_reqitarpit] = ACTIONS(161),
    [anon_sym_reqpass] = ACTIONS(161),
    [anon_sym_reqrep] = ACTIONS(161),
    [anon_sym_reqsetbe] = ACTIONS(161),
    [anon_sym_reqtarpit] = ACTIONS(161),
    [anon_sym_rspadd] = ACTIONS(161),
    [anon_sym_rspdel] = ACTIONS(161),
    [anon_sym_rspdeny] = ACTIONS(161),
    [anon_sym_rspidel] = ACTIONS(161),
    [anon_sym_rspideny] = ACTIONS(161),
    [anon_sym_rspirep] = ACTIONS(161),
    [anon_sym_rsprep] = ACTIONS(161),
    [anon_sym_option] = ACTIONS(167),
    [anon_sym_timeout] = ACTIONS(170),
    [anon_sym_stats] = ACTIONS(173),
    [anon_sym_http_DASHrequest] = ACTIONS(176),
    [anon_sym_http_DASHresponse] = ACTIONS(176),
    [anon_sym_http_DASHcheck] = ACTIONS(179),
    [anon_sym_tcp_DASHrequest] = ACTIONS(182),
    [anon_sym_tcp_DASHresponse] = ACTIONS(185),
    [anon_sym_stick] = ACTIONS(188),
    [anon_sym_stick_DASHtable] = ACTIONS(191),
    [anon_sym_capture] = ACTIONS(194),
    [anon_sym_use_DASHserver] = ACTIONS(191),
    [anon_sym_monitor] = ACTIONS(197),
    [anon_sym_rate_DASHlimit] = ACTIONS(200),
    [anon_sym_persist] = ACTIONS(203),
  },
  [21] = {
    [sym__statement] = STATE(20),
    [sym_section] = STATE(20),
    [sym_section_name] = STATE(22),
    [sym_directive] = STATE(20),
    [sym_keyword] = STATE(2),
    [sym_keyword_combination] = STATE(2),
    [aux_sym_source_file_repeat1] = STATE(20),
    [ts_builtin_sym_end] = ACTIONS(206),
    [sym_comment] = ACTIONS(208),
    [anon_sym_global] = ACTIONS(9),
    [anon_sym_defaults] = ACTIONS(9),
    [anon_sym_frontend] = ACTIONS(9),
    [anon_sym_backend] = ACTIONS(9),
    [anon_sym_listen] = ACTIONS(9),
    [anon_sym_peers] = ACTIONS(9),
    [anon_sym_resolvers] = ACTIONS(9),
    [anon_sym_userlist] = ACTIONS(9),
    [anon_sym_aggregations] = ACTIONS(9),
    [anon_sym_acl] = ACTIONS(11),
    [anon_sym_bind] = ACTIONS(13),
    [anon_sym_server] = ACTIONS(11),
    [anon_sym_balance] = ACTIONS(11),
    [anon_sym_mode] = ACTIONS(11),
    [anon_sym_maxconn] = ACTIONS(11),
    [anon_sym_user] = ACTIONS(13),
    [anon_sym_group] = ACTIONS(11),
    [anon_sym_daemon] = ACTIONS(11),
    [anon_sym_log] = ACTIONS(13),
    [anon_sym_retries] = ACTIONS(11),
    [anon_sym_cookie] = ACTIONS(11),
    [anon_sym_errorfile] = ACTIONS(11),
    [anon_sym_default_backend] = ACTIONS(11),
    [anon_sym_use_backend] = ACTIONS(11),
    [anon_sym_compression] = ACTIONS(11),
    [anon_sym_redirect] = ACTIONS(11),
    [anon_sym_source] = ACTIONS(11),
    [anon_sym_id] = ACTIONS(11),
    [anon_sym_disabled] = ACTIONS(11),
    [anon_sym_enabled] = ACTIONS(11),
    [anon_sym_dispatch] = ACTIONS(11),
    [anon_sym_backlog] = ACTIONS(11),
    [anon_sym_description] = ACTIONS(11),
    [anon_sym_chroot] = ACTIONS(11),
    [anon_sym_ca_DASHbase] = ACTIONS(11),
    [anon_sym_crt_DASHbase] = ACTIONS(11),
    [anon_sym_nbproc] = ACTIONS(11),
    [anon_sym_cpu_DASHmap] = ACTIONS(11),
    [anon_sym_lua_DASHload] = ACTIONS(11),
    [anon_sym_monitor_DASHnet] = ACTIONS(11),
    [anon_sym_monitor_DASHuri] = ACTIONS(11),
    [anon_sym_grace] = ACTIONS(11),
    [anon_sym_hash_DASHtype] = ACTIONS(11),
    [anon_sym_force_DASHpersist] = ACTIONS(11),
    [anon_sym_ignore_DASHpersist] = ACTIONS(11),
    [anon_sym_bind_DASHprocess] = ACTIONS(11),
    [anon_sym_default_DASHserver] = ACTIONS(11),
    [anon_sym_log_DASHformat] = ACTIONS(11),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(11),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(11),
    [anon_sym_nameserver] = ACTIONS(11),
    [anon_sym_peer] = ACTIONS(13),
    [anon_sym_resolution_pool_size] = ACTIONS(11),
    [anon_sym_resolve_retries] = ACTIONS(11),
    [anon_sym_reqadd] = ACTIONS(11),
    [anon_sym_reqallow] = ACTIONS(11),
    [anon_sym_reqdel] = ACTIONS(11),
    [anon_sym_reqdeny] = ACTIONS(11),
    [anon_sym_reqiallow] = ACTIONS(11),
    [anon_sym_reqidel] = ACTIONS(11),
    [anon_sym_reqideny] = ACTIONS(11),
    [anon_sym_reqipass] = ACTIONS(11),
    [anon_sym_reqirep] = ACTIONS(11),
    [anon_sym_reqisetbe] = ACTIONS(11),
    [anon_sym_reqitarpit] = ACTIONS(11),
    [anon_sym_reqpass] = ACTIONS(11),
    [anon_sym_reqrep] = ACTIONS(11),
    [anon_sym_reqsetbe] = ACTIONS(11),
    [anon_sym_reqtarpit] = ACTIONS(11),
    [anon_sym_rspadd] = ACTIONS(11),
    [anon_sym_rspdel] = ACTIONS(11),
    [anon_sym_rspdeny] = ACTIONS(11),
    [anon_sym_rspidel] = ACTIONS(11),
    [anon_sym_rspideny] = ACTIONS(11),
    [anon_sym_rspirep] = ACTIONS(11),
    [anon_sym_rsprep] = ACTIONS(11),
    [anon_sym_option] = ACTIONS(15),
    [anon_sym_timeout] = ACTIONS(17),
    [anon_sym_stats] = ACTIONS(19),
    [anon_sym_http_DASHrequest] = ACTIONS(21),
    [anon_sym_http_DASHresponse] = ACTIONS(21),
    [anon_sym_http_DASHcheck] = ACTIONS(23),
    [anon_sym_tcp_DASHrequest] = ACTIONS(25),
    [anon_sym_tcp_DASHresponse] = ACTIONS(27),
    [anon_sym_stick] = ACTIONS(29),
    [anon_sym_stick_DASHtable] = ACTIONS(31),
    [anon_sym_capture] = ACTIONS(33),
    [anon_sym_use_DASHserver] = ACTIONS(31),
    [anon_sym_monitor] = ACTIONS(35),
    [anon_sym_rate_DASHlimit] = ACTIONS(37),
    [anon_sym_persist] = ACTIONS(39),
  },
  [22] = {
    [sym_directive] = STATE(25),
    [sym_keyword] = STATE(2),
    [sym_keyword_combination] = STATE(2),
    [aux_sym_section_repeat1] = STATE(25),
    [ts_builtin_sym_end] = ACTIONS(210),
    [sym_comment] = ACTIONS(210),
    [anon_sym_global] = ACTIONS(212),
    [anon_sym_defaults] = ACTIONS(212),
    [anon_sym_frontend] = ACTIONS(212),
    [anon_sym_backend] = ACTIONS(212),
    [anon_sym_listen] = ACTIONS(212),
    [anon_sym_peers] = ACTIONS(212),
    [anon_sym_resolvers] = ACTIONS(212),
    [anon_sym_userlist] = ACTIONS(212),
    [anon_sym_aggregations] = ACTIONS(212),
    [anon_sym_acl] = ACTIONS(214),
    [anon_sym_bind] = ACTIONS(214),
    [anon_sym_server] = ACTIONS(214),
    [anon_sym_balance] = ACTIONS(214),
    [anon_sym_mode] = ACTIONS(214),
    [anon_sym_maxconn] = ACTIONS(214),
    [anon_sym_user] = ACTIONS(214),
    [anon_sym_group] = ACTIONS(214),
    [anon_sym_daemon] = ACTIONS(214),
    [anon_sym_log] = ACTIONS(214),
    [anon_sym_retries] = ACTIONS(214),
    [anon_sym_cookie] = ACTIONS(214),
    [anon_sym_errorfile] = ACTIONS(214),
    [anon_sym_default_backend] = ACTIONS(214),
    [anon_sym_use_backend] = ACTIONS(214),
    [anon_sym_compression] = ACTIONS(214),
    [anon_sym_redirect] = ACTIONS(214),
    [anon_sym_source] = ACTIONS(214),
    [anon_sym_id] = ACTIONS(214),
    [anon_sym_disabled] = ACTIONS(214),
    [anon_sym_enabled] = ACTIONS(214),
    [anon_sym_dispatch] = ACTIONS(214),
    [anon_sym_backlog] = ACTIONS(214),
    [anon_sym_description] = ACTIONS(214),
    [anon_sym_chroot] = ACTIONS(214),
    [anon_sym_ca_DASHbase] = ACTIONS(214),
    [anon_sym_crt_DASHbase] = ACTIONS(214),
    [anon_sym_nbproc] = ACTIONS(214),
    [anon_sym_cpu_DASHmap] = ACTIONS(214),
    [anon_sym_lua_DASHload] = ACTIONS(214),
    [anon_sym_monitor_DASHnet] = ACTIONS(214),
    [anon_sym_monitor_DASHuri] = ACTIONS(214),
    [anon_sym_grace] = ACTIONS(214),
    [anon_sym_hash_DASHtype] = ACTIONS(214),
    [anon_sym_force_DASHpersist] = ACTIONS(214),
    [anon_sym_ignore_DASHpersist] = ACTIONS(214),
    [anon_sym_bind_DASHprocess] = ACTIONS(214),
    [anon_sym_default_DASHserver] = ACTIONS(214),
    [anon_sym_log_DASHformat] = ACTIONS(214),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(214),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(214),
    [anon_sym_nameserver] = ACTIONS(214),
    [anon_sym_peer] = ACTIONS(214),
    [anon_sym_resolution_pool_size] = ACTIONS(214),
    [anon_sym_resolve_retries] = ACTIONS(214),
    [anon_sym_reqadd] = ACTIONS(214),
    [anon_sym_reqallow] = ACTIONS(214),
    [anon_sym_reqdel] = ACTIONS(214),
    [anon_sym_reqdeny] = ACTIONS(214),
    [anon_sym_reqiallow] = ACTIONS(214),
    [anon_sym_reqidel] = ACTIONS(214),
    [anon_sym_reqideny] = ACTIONS(214),
    [anon_sym_reqipass] = ACTIONS(214),
    [anon_sym_reqirep] = ACTIONS(214),
    [anon_sym_reqisetbe] = ACTIONS(214),
    [anon_sym_reqitarpit] = ACTIONS(214),
    [anon_sym_reqpass] = ACTIONS(214),
    [anon_sym_reqrep] = ACTIONS(214),
    [anon_sym_reqsetbe] = ACTIONS(214),
    [anon_sym_reqtarpit] = ACTIONS(214),
    [anon_sym_rspadd] = ACTIONS(214),
    [anon_sym_rspdel] = ACTIONS(214),
    [anon_sym_rspdeny] = ACTIONS(214),
    [anon_sym_rspidel] = ACTIONS(214),
    [anon_sym_rspideny] = ACTIONS(214),
    [anon_sym_rspirep] = ACTIONS(214),
    [anon_sym_rsprep] = ACTIONS(214),
    [anon_sym_option] = ACTIONS(217),
    [anon_sym_timeout] = ACTIONS(220),
    [anon_sym_stats] = ACTIONS(223),
    [anon_sym_http_DASHrequest] = ACTIONS(226),
    [anon_sym_http_DASHresponse] = ACTIONS(226),
    [anon_sym_http_DASHcheck] = ACTIONS(229),
    [anon_sym_tcp_DASHrequest] = ACTIONS(232),
    [anon_sym_tcp_DASHresponse] = ACTIONS(235),
    [anon_sym_stick] = ACTIONS(238),
    [anon_sym_stick_DASHtable] = ACTIONS(241),
    [anon_sym_capture] = ACTIONS(244),
    [anon_sym_use_DASHserver] = ACTIONS(241),
    [anon_sym_monitor] = ACTIONS(247),
    [anon_sym_rate_DASHlimit] = ACTIONS(250),
    [anon_sym_persist] = ACTIONS(253),
    [sym_identifier] = ACTIONS(256),
  },
  [23] = {
    [sym_directive] = STATE(23),
    [sym_keyword] = STATE(2),
    [sym_keyword_combination] = STATE(2),
    [aux_sym_section_repeat1] = STATE(23),
    [ts_builtin_sym_end] = ACTIONS(258),
    [sym_comment] = ACTIONS(258),
    [anon_sym_global] = ACTIONS(258),
    [anon_sym_defaults] = ACTIONS(258),
    [anon_sym_frontend] = ACTIONS(258),
    [anon_sym_backend] = ACTIONS(258),
    [anon_sym_listen] = ACTIONS(258),
    [anon_sym_peers] = ACTIONS(258),
    [anon_sym_resolvers] = ACTIONS(258),
    [anon_sym_userlist] = ACTIONS(258),
    [anon_sym_aggregations] = ACTIONS(258),
    [anon_sym_acl] = ACTIONS(260),
    [anon_sym_bind] = ACTIONS(263),
    [anon_sym_server] = ACTIONS(260),
    [anon_sym_balance] = ACTIONS(260),
    [anon_sym_mode] = ACTIONS(260),
    [anon_sym_maxconn] = ACTIONS(260),
    [anon_sym_user] = ACTIONS(263),
    [anon_sym_group] = ACTIONS(260),
    [anon_sym_daemon] = ACTIONS(260),
    [anon_sym_log] = ACTIONS(263),
    [anon_sym_retries] = ACTIONS(260),
    [anon_sym_cookie] = ACTIONS(260),
    [anon_sym_errorfile] = ACTIONS(260),
    [anon_sym_default_backend] = ACTIONS(260),
    [anon_sym_use_backend] = ACTIONS(260),
    [anon_sym_compression] = ACTIONS(260),
    [anon_sym_redirect] = ACTIONS(260),
    [anon_sym_source] = ACTIONS(260),
    [anon_sym_id] = ACTIONS(260),
    [anon_sym_disabled] = ACTIONS(260),
    [anon_sym_enabled] = ACTIONS(260),
    [anon_sym_dispatch] = ACTIONS(260),
    [anon_sym_backlog] = ACTIONS(260),
    [anon_sym_description] = ACTIONS(260),
    [anon_sym_chroot] = ACTIONS(260),
    [anon_sym_ca_DASHbase] = ACTIONS(260),
    [anon_sym_crt_DASHbase] = ACTIONS(260),
    [anon_sym_nbproc] = ACTIONS(260),
    [anon_sym_cpu_DASHmap] = ACTIONS(260),
    [anon_sym_lua_DASHload] = ACTIONS(260),
    [anon_sym_monitor_DASHnet] = ACTIONS(260),
    [anon_sym_monitor_DASHuri] = ACTIONS(260),
    [anon_sym_grace] = ACTIONS(260),
    [anon_sym_hash_DASHtype] = ACTIONS(260),
    [anon_sym_force_DASHpersist] = ACTIONS(260),
    [anon_sym_ignore_DASHpersist] = ACTIONS(260),
    [anon_sym_bind_DASHprocess] = ACTIONS(260),
    [anon_sym_default_DASHserver] = ACTIONS(260),
    [anon_sym_log_DASHformat] = ACTIONS(260),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(260),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(260),
    [anon_sym_nameserver] = ACTIONS(260),
    [anon_sym_peer] = ACTIONS(263),
    [anon_sym_resolution_pool_size] = ACTIONS(260),
    [anon_sym_resolve_retries] = ACTIONS(260),
    [anon_sym_reqadd] = ACTIONS(260),
    [anon_sym_reqallow] = ACTIONS(260),
    [anon_sym_reqdel] = ACTIONS(260),
    [anon_sym_reqdeny] = ACTIONS(260),
    [anon_sym_reqiallow] = ACTIONS(260),
    [anon_sym_reqidel] = ACTIONS(260),
    [anon_sym_reqideny] = ACTIONS(260),
    [anon_sym_reqipass] = ACTIONS(260),
    [anon_sym_reqirep] = ACTIONS(260),
    [anon_sym_reqisetbe] = ACTIONS(260),
    [anon_sym_reqitarpit] = ACTIONS(260),
    [anon_sym_reqpass] = ACTIONS(260),
    [anon_sym_reqrep] = ACTIONS(260),
    [anon_sym_reqsetbe] = ACTIONS(260),
    [anon_sym_reqtarpit] = ACTIONS(260),
    [anon_sym_rspadd] = ACTIONS(260),
    [anon_sym_rspdel] = ACTIONS(260),
    [anon_sym_rspdeny] = ACTIONS(260),
    [anon_sym_rspidel] = ACTIONS(260),
    [anon_sym_rspideny] = ACTIONS(260),
    [anon_sym_rspirep] = ACTIONS(260),
    [anon_sym_rsprep] = ACTIONS(260),
    [anon_sym_option] = ACTIONS(266),
    [anon_sym_timeout] = ACTIONS(269),
    [anon_sym_stats] = ACTIONS(272),
    [anon_sym_http_DASHrequest] = ACTIONS(275),
    [anon_sym_http_DASHresponse] = ACTIONS(275),
    [anon_sym_http_DASHcheck] = ACTIONS(278),
    [anon_sym_tcp_DASHrequest] = ACTIONS(281),
    [anon_sym_tcp_DASHresponse] = ACTIONS(284),
    [anon_sym_stick] = ACTIONS(287),
    [anon_sym_stick_DASHtable] = ACTIONS(290),
    [anon_sym_capture] = ACTIONS(293),
    [anon_sym_use_DASHserver] = ACTIONS(290),
    [anon_sym_monitor] = ACTIONS(296),
    [anon_sym_rate_DASHlimit] = ACTIONS(299),
    [anon_sym_persist] = ACTIONS(302),
  },
  [24] = {
    [sym_directive] = STATE(26),
    [sym_keyword] = STATE(2),
    [sym_keyword_combination] = STATE(2),
    [aux_sym_section_repeat1] = STATE(26),
    [ts_builtin_sym_end] = ACTIONS(305),
    [sym_comment] = ACTIONS(305),
    [anon_sym_global] = ACTIONS(305),
    [anon_sym_defaults] = ACTIONS(305),
    [anon_sym_frontend] = ACTIONS(305),
    [anon_sym_backend] = ACTIONS(305),
    [anon_sym_listen] = ACTIONS(305),
    [anon_sym_peers] = ACTIONS(305),
    [anon_sym_resolvers] = ACTIONS(305),
    [anon_sym_userlist] = ACTIONS(305),
    [anon_sym_aggregations] = ACTIONS(305),
    [anon_sym_acl] = ACTIONS(307),
    [anon_sym_bind] = ACTIONS(310),
    [anon_sym_server] = ACTIONS(307),
    [anon_sym_balance] = ACTIONS(307),
    [anon_sym_mode] = ACTIONS(307),
    [anon_sym_maxconn] = ACTIONS(307),
    [anon_sym_user] = ACTIONS(310),
    [anon_sym_group] = ACTIONS(307),
    [anon_sym_daemon] = ACTIONS(307),
    [anon_sym_log] = ACTIONS(310),
    [anon_sym_retries] = ACTIONS(307),
    [anon_sym_cookie] = ACTIONS(307),
    [anon_sym_errorfile] = ACTIONS(307),
    [anon_sym_default_backend] = ACTIONS(307),
    [anon_sym_use_backend] = ACTIONS(307),
    [anon_sym_compression] = ACTIONS(307),
    [anon_sym_redirect] = ACTIONS(307),
    [anon_sym_source] = ACTIONS(307),
    [anon_sym_id] = ACTIONS(307),
    [anon_sym_disabled] = ACTIONS(307),
    [anon_sym_enabled] = ACTIONS(307),
    [anon_sym_dispatch] = ACTIONS(307),
    [anon_sym_backlog] = ACTIONS(307),
    [anon_sym_description] = ACTIONS(307),
    [anon_sym_chroot] = ACTIONS(307),
    [anon_sym_ca_DASHbase] = ACTIONS(307),
    [anon_sym_crt_DASHbase] = ACTIONS(307),
    [anon_sym_nbproc] = ACTIONS(307),
    [anon_sym_cpu_DASHmap] = ACTIONS(307),
    [anon_sym_lua_DASHload] = ACTIONS(307),
    [anon_sym_monitor_DASHnet] = ACTIONS(307),
    [anon_sym_monitor_DASHuri] = ACTIONS(307),
    [anon_sym_grace] = ACTIONS(307),
    [anon_sym_hash_DASHtype] = ACTIONS(307),
    [anon_sym_force_DASHpersist] = ACTIONS(307),
    [anon_sym_ignore_DASHpersist] = ACTIONS(307),
    [anon_sym_bind_DASHprocess] = ACTIONS(307),
    [anon_sym_default_DASHserver] = ACTIONS(307),
    [anon_sym_log_DASHformat] = ACTIONS(307),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(307),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(307),
    [anon_sym_nameserver] = ACTIONS(307),
    [anon_sym_peer] = ACTIONS(310),
    [anon_sym_resolution_pool_size] = ACTIONS(307),
    [anon_sym_resolve_retries] = ACTIONS(307),
    [anon_sym_reqadd] = ACTIONS(307),
    [anon_sym_reqallow] = ACTIONS(307),
    [anon_sym_reqdel] = ACTIONS(307),
    [anon_sym_reqdeny] = ACTIONS(307),
    [anon_sym_reqiallow] = ACTIONS(307),
    [anon_sym_reqidel] = ACTIONS(307),
    [anon_sym_reqideny] = ACTIONS(307),
    [anon_sym_reqipass] = ACTIONS(307),
    [anon_sym_reqirep] = ACTIONS(307),
    [anon_sym_reqisetbe] = ACTIONS(307),
    [anon_sym_reqitarpit] = ACTIONS(307),
    [anon_sym_reqpass] = ACTIONS(307),
    [anon_sym_reqrep] = ACTIONS(307),
    [anon_sym_reqsetbe] = ACTIONS(307),
    [anon_sym_reqtarpit] = ACTIONS(307),
    [anon_sym_rspadd] = ACTIONS(307),
    [anon_sym_rspdel] = ACTIONS(307),
    [anon_sym_rspdeny] = ACTIONS(307),
    [anon_sym_rspidel] = ACTIONS(307),
    [anon_sym_rspideny] = ACTIONS(307),
    [anon_sym_rspirep] = ACTIONS(307),
    [anon_sym_rsprep] = ACTIONS(307),
    [anon_sym_option] = ACTIONS(313),
    [anon_sym_timeout] = ACTIONS(316),
    [anon_sym_stats] = ACTIONS(319),
    [anon_sym_http_DASHrequest] = ACTIONS(322),
    [anon_sym_http_DASHresponse] = ACTIONS(322),
    [anon_sym_http_DASHcheck] = ACTIONS(325),
    [anon_sym_tcp_DASHrequest] = ACTIONS(328),
    [anon_sym_tcp_DASHresponse] = ACTIONS(331),
    [anon_sym_stick] = ACTIONS(334),
    [anon_sym_stick_DASHtable] = ACTIONS(337),
    [anon_sym_capture] = ACTIONS(340),
    [anon_sym_use_DASHserver] = ACTIONS(337),
    [anon_sym_monitor] = ACTIONS(343),
    [anon_sym_rate_DASHlimit] = ACTIONS(346),
    [anon_sym_persist] = ACTIONS(349),
  },
  [25] = {
    [sym_directive] = STATE(23),
    [sym_keyword] = STATE(2),
    [sym_keyword_combination] = STATE(2),
    [aux_sym_section_repeat1] = STATE(23),
    [ts_builtin_sym_end] = ACTIONS(352),
    [sym_comment] = ACTIONS(352),
    [anon_sym_global] = ACTIONS(352),
    [anon_sym_defaults] = ACTIONS(352),
    [anon_sym_frontend] = ACTIONS(352),
    [anon_sym_backend] = ACTIONS(352),
    [anon_sym_listen] = ACTIONS(352),
    [anon_sym_peers] = ACTIONS(352),
    [anon_sym_resolvers] = ACTIONS(352),
    [anon_sym_userlist] = ACTIONS(352),
    [anon_sym_aggregations] = ACTIONS(352),
    [anon_sym_acl] = ACTIONS(354),
    [anon_sym_bind] = ACTIONS(357),
    [anon_sym_server] = ACTIONS(354),
    [anon_sym_balance] = ACTIONS(354),
    [anon_sym_mode] = ACTIONS(354),
    [anon_sym_maxconn] = ACTIONS(354),
    [anon_sym_user] = ACTIONS(357),
    [anon_sym_group] = ACTIONS(354),
    [anon_sym_daemon] = ACTIONS(354),
    [anon_sym_log] = ACTIONS(357),
    [anon_sym_retries] = ACTIONS(354),
    [anon_sym_cookie] = ACTIONS(354),
    [anon_sym_errorfile] = ACTIONS(354),
    [anon_sym_default_backend] = ACTIONS(354),
    [anon_sym_use_backend] = ACTIONS(354),
    [anon_sym_compression] = ACTIONS(354),
    [anon_sym_redirect] = ACTIONS(354),
    [anon_sym_source] = ACTIONS(354),
    [anon_sym_id] = ACTIONS(354),
    [anon_sym_disabled] = ACTIONS(354),
    [anon_sym_enabled] = ACTIONS(354),
    [anon_sym_dispatch] = ACTIONS(354),
    [anon_sym_backlog] = ACTIONS(354),
    [anon_sym_description] = ACTIONS(354),
    [anon_sym_chroot] = ACTIONS(354),
    [anon_sym_ca_DASHbase] = ACTIONS(354),
    [anon_sym_crt_DASHbase] = ACTIONS(354),
    [anon_sym_nbproc] = ACTIONS(354),
    [anon_sym_cpu_DASHmap] = ACTIONS(354),
    [anon_sym_lua_DASHload] = ACTIONS(354),
    [anon_sym_monitor_DASHnet] = ACTIONS(354),
    [anon_sym_monitor_DASHuri] = ACTIONS(354),
    [anon_sym_grace] = ACTIONS(354),
    [anon_sym_hash_DASHtype] = ACTIONS(354),
    [anon_sym_force_DASHpersist] = ACTIONS(354),
    [anon_sym_ignore_DASHpersist] = ACTIONS(354),
    [anon_sym_bind_DASHprocess] = ACTIONS(354),
    [anon_sym_default_DASHserver] = ACTIONS(354),
    [anon_sym_log_DASHformat] = ACTIONS(354),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(354),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(354),
    [anon_sym_nameserver] = ACTIONS(354),
    [anon_sym_peer] = ACTIONS(357),
    [anon_sym_resolution_pool_size] = ACTIONS(354),
    [anon_sym_resolve_retries] = ACTIONS(354),
    [anon_sym_reqadd] = ACTIONS(354),
    [anon_sym_reqallow] = ACTIONS(354),
    [anon_sym_reqdel] = ACTIONS(354),
    [anon_sym_reqdeny] = ACTIONS(354),
    [anon_sym_reqiallow] = ACTIONS(354),
    [anon_sym_reqidel] = ACTIONS(354),
    [anon_sym_reqideny] = ACTIONS(354),
    [anon_sym_reqipass] = ACTIONS(354),
    [anon_sym_reqirep] = ACTIONS(354),
    [anon_sym_reqisetbe] = ACTIONS(354),
    [anon_sym_reqitarpit] = ACTIONS(354),
    [anon_sym_reqpass] = ACTIONS(354),
    [anon_sym_reqrep] = ACTIONS(354),
    [anon_sym_reqsetbe] = ACTIONS(354),
    [anon_sym_reqtarpit] = ACTIONS(354),
    [anon_sym_rspadd] = ACTIONS(354),
    [anon_sym_rspdel] = ACTIONS(354),
    [anon_sym_rspdeny] = ACTIONS(354),
    [anon_sym_rspidel] = ACTIONS(354),
    [anon_sym_rspideny] = ACTIONS(354),
    [anon_sym_rspirep] = ACTIONS(354),
    [anon_sym_rsprep] = ACTIONS(354),
    [anon_sym_option] = ACTIONS(360),
    [anon_sym_timeout] = ACTIONS(363),
    [anon_sym_stats] = ACTIONS(366),
    [anon_sym_http_DASHrequest] = ACTIONS(369),
    [anon_sym_http_DASHresponse] = ACTIONS(369),
    [anon_sym_http_DASHcheck] = ACTIONS(372),
    [anon_sym_tcp_DASHrequest] = ACTIONS(375),
    [anon_sym_tcp_DASHresponse] = ACTIONS(378),
    [anon_sym_stick] = ACTIONS(381),
    [anon_sym_stick_DASHtable] = ACTIONS(384),
    [anon_sym_capture] = ACTIONS(387),
    [anon_sym_use_DASHserver] = ACTIONS(384),
    [anon_sym_monitor] = ACTIONS(390),
    [anon_sym_rate_DASHlimit] = ACTIONS(393),
    [anon_sym_persist] = ACTIONS(396),
  },
  [26] = {
    [sym_directive] = STATE(23),
    [sym_keyword] = STATE(2),
    [sym_keyword_combination] = STATE(2),
    [aux_sym_section_repeat1] = STATE(23),
    [ts_builtin_sym_end] = ACTIONS(399),
    [sym_comment] = ACTIONS(399),
    [anon_sym_global] = ACTIONS(399),
    [anon_sym_defaults] = ACTIONS(399),
    [anon_sym_frontend] = ACTIONS(399),
    [anon_sym_backend] = ACTIONS(399),
    [anon_sym_listen] = ACTIONS(399),
    [anon_sym_peers] = ACTIONS(399),
    [anon_sym_resolvers] = ACTIONS(399),
    [anon_sym_userlist] = ACTIONS(399),
    [anon_sym_aggregations] = ACTIONS(399),
    [anon_sym_acl] = ACTIONS(401),
    [anon_sym_bind] = ACTIONS(404),
    [anon_sym_server] = ACTIONS(401),
    [anon_sym_balance] = ACTIONS(401),
    [anon_sym_mode] = ACTIONS(401),
    [anon_sym_maxconn] = ACTIONS(401),
    [anon_sym_user] = ACTIONS(404),
    [anon_sym_group] = ACTIONS(401),
    [anon_sym_daemon] = ACTIONS(401),
    [anon_sym_log] = ACTIONS(404),
    [anon_sym_retries] = ACTIONS(401),
    [anon_sym_cookie] = ACTIONS(401),
    [anon_sym_errorfile] = ACTIONS(401),
    [anon_sym_default_backend] = ACTIONS(401),
    [anon_sym_use_backend] = ACTIONS(401),
    [anon_sym_compression] = ACTIONS(401),
    [anon_sym_redirect] = ACTIONS(401),
    [anon_sym_source] = ACTIONS(401),
    [anon_sym_id] = ACTIONS(401),
    [anon_sym_disabled] = ACTIONS(401),
    [anon_sym_enabled] = ACTIONS(401),
    [anon_sym_dispatch] = ACTIONS(401),
    [anon_sym_backlog] = ACTIONS(401),
    [anon_sym_description] = ACTIONS(401),
    [anon_sym_chroot] = ACTIONS(401),
    [anon_sym_ca_DASHbase] = ACTIONS(401),
    [anon_sym_crt_DASHbase] = ACTIONS(401),
    [anon_sym_nbproc] = ACTIONS(401),
    [anon_sym_cpu_DASHmap] = ACTIONS(401),
    [anon_sym_lua_DASHload] = ACTIONS(401),
    [anon_sym_monitor_DASHnet] = ACTIONS(401),
    [anon_sym_monitor_DASHuri] = ACTIONS(401),
    [anon_sym_grace] = ACTIONS(401),
    [anon_sym_hash_DASHtype] = ACTIONS(401),
    [anon_sym_force_DASHpersist] = ACTIONS(401),
    [anon_sym_ignore_DASHpersist] = ACTIONS(401),
    [anon_sym_bind_DASHprocess] = ACTIONS(401),
    [anon_sym_default_DASHserver] = ACTIONS(401),
    [anon_sym_log_DASHformat] = ACTIONS(401),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(401),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(401),
    [anon_sym_nameserver] = ACTIONS(401),
    [anon_sym_peer] = ACTIONS(404),
    [anon_sym_resolution_pool_size] = ACTIONS(401),
    [anon_sym_resolve_retries] = ACTIONS(401),
    [anon_sym_reqadd] = ACTIONS(401),
    [anon_sym_reqallow] = ACTIONS(401),
    [anon_sym_reqdel] = ACTIONS(401),
    [anon_sym_reqdeny] = ACTIONS(401),
    [anon_sym_reqiallow] = ACTIONS(401),
    [anon_sym_reqidel] = ACTIONS(401),
    [anon_sym_reqideny] = ACTIONS(401),
    [anon_sym_reqipass] = ACTIONS(401),
    [anon_sym_reqirep] = ACTIONS(401),
    [anon_sym_reqisetbe] = ACTIONS(401),
    [anon_sym_reqitarpit] = ACTIONS(401),
    [anon_sym_reqpass] = ACTIONS(401),
    [anon_sym_reqrep] = ACTIONS(401),
    [anon_sym_reqsetbe] = ACTIONS(401),
    [anon_sym_reqtarpit] = ACTIONS(401),
    [anon_sym_rspadd] = ACTIONS(401),
    [anon_sym_rspdel] = ACTIONS(401),
    [anon_sym_rspdeny] = ACTIONS(401),
    [anon_sym_rspidel] = ACTIONS(401),
    [anon_sym_rspideny] = ACTIONS(401),
    [anon_sym_rspirep] = ACTIONS(401),
    [anon_sym_rsprep] = ACTIONS(401),
    [anon_sym_option] = ACTIONS(407),
    [anon_sym_timeout] = ACTIONS(410),
    [anon_sym_stats] = ACTIONS(413),
    [anon_sym_http_DASHrequest] = ACTIONS(416),
    [anon_sym_http_DASHresponse] = ACTIONS(416),
    [anon_sym_http_DASHcheck] = ACTIONS(419),
    [anon_sym_tcp_DASHrequest] = ACTIONS(422),
    [anon_sym_tcp_DASHresponse] = ACTIONS(425),
    [anon_sym_stick] = ACTIONS(428),
    [anon_sym_stick_DASHtable] = ACTIONS(431),
    [anon_sym_capture] = ACTIONS(434),
    [anon_sym_use_DASHserver] = ACTIONS(431),
    [anon_sym_monitor] = ACTIONS(437),
    [anon_sym_rate_DASHlimit] = ACTIONS(440),
    [anon_sym_persist] = ACTIONS(443),
  },
  [27] = {
    [ts_builtin_sym_end] = ACTIONS(446),
    [sym_comment] = ACTIONS(446),
    [anon_sym_global] = ACTIONS(448),
    [anon_sym_defaults] = ACTIONS(448),
    [anon_sym_frontend] = ACTIONS(448),
    [anon_sym_backend] = ACTIONS(448),
    [anon_sym_listen] = ACTIONS(448),
    [anon_sym_peers] = ACTIONS(448),
    [anon_sym_resolvers] = ACTIONS(448),
    [anon_sym_userlist] = ACTIONS(448),
    [anon_sym_aggregations] = ACTIONS(448),
    [anon_sym_acl] = ACTIONS(448),
    [anon_sym_bind] = ACTIONS(448),
    [anon_sym_server] = ACTIONS(448),
    [anon_sym_balance] = ACTIONS(448),
    [anon_sym_mode] = ACTIONS(448),
    [anon_sym_maxconn] = ACTIONS(448),
    [anon_sym_user] = ACTIONS(448),
    [anon_sym_group] = ACTIONS(448),
    [anon_sym_daemon] = ACTIONS(448),
    [anon_sym_log] = ACTIONS(448),
    [anon_sym_retries] = ACTIONS(448),
    [anon_sym_cookie] = ACTIONS(448),
    [anon_sym_errorfile] = ACTIONS(448),
    [anon_sym_default_backend] = ACTIONS(448),
    [anon_sym_use_backend] = ACTIONS(448),
    [anon_sym_compression] = ACTIONS(448),
    [anon_sym_redirect] = ACTIONS(448),
    [anon_sym_source] = ACTIONS(448),
    [anon_sym_id] = ACTIONS(448),
    [anon_sym_disabled] = ACTIONS(448),
    [anon_sym_enabled] = ACTIONS(448),
    [anon_sym_dispatch] = ACTIONS(448),
    [anon_sym_backlog] = ACTIONS(448),
    [anon_sym_description] = ACTIONS(448),
    [anon_sym_chroot] = ACTIONS(448),
    [anon_sym_ca_DASHbase] = ACTIONS(448),
    [anon_sym_crt_DASHbase] = ACTIONS(448),
    [anon_sym_nbproc] = ACTIONS(448),
    [anon_sym_cpu_DASHmap] = ACTIONS(448),
    [anon_sym_lua_DASHload] = ACTIONS(448),
    [anon_sym_monitor_DASHnet] = ACTIONS(448),
    [anon_sym_monitor_DASHuri] = ACTIONS(448),
    [anon_sym_grace] = ACTIONS(448),
    [anon_sym_hash_DASHtype] = ACTIONS(448),
    [anon_sym_force_DASHpersist] = ACTIONS(448),
    [anon_sym_ignore_DASHpersist] = ACTIONS(448),
    [anon_sym_bind_DASHprocess] = ACTIONS(448),
    [anon_sym_default_DASHserver] = ACTIONS(448),
    [anon_sym_log_DASHformat] = ACTIONS(448),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(448),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(448),
    [anon_sym_nameserver] = ACTIONS(448),
    [anon_sym_peer] = ACTIONS(448),
    [anon_sym_resolution_pool_size] = ACTIONS(448),
    [anon_sym_resolve_retries] = ACTIONS(448),
    [anon_sym_reqadd] = ACTIONS(448),
    [anon_sym_reqallow] = ACTIONS(448),
    [anon_sym_reqdel] = ACTIONS(448),
    [anon_sym_reqdeny] = ACTIONS(448),
    [anon_sym_reqiallow] = ACTIONS(448),
    [anon_sym_reqidel] = ACTIONS(448),
    [anon_sym_reqideny] = ACTIONS(448),
    [anon_sym_reqipass] = ACTIONS(448),
    [anon_sym_reqirep] = ACTIONS(448),
    [anon_sym_reqisetbe] = ACTIONS(448),
    [anon_sym_reqitarpit] = ACTIONS(448),
    [anon_sym_reqpass] = ACTIONS(448),
    [anon_sym_reqrep] = ACTIONS(448),
    [anon_sym_reqsetbe] = ACTIONS(448),
    [anon_sym_reqtarpit] = ACTIONS(448),
    [anon_sym_rspadd] = ACTIONS(448),
    [anon_sym_rspdel] = ACTIONS(448),
    [anon_sym_rspdeny] = ACTIONS(448),
    [anon_sym_rspidel] = ACTIONS(448),
    [anon_sym_rspideny] = ACTIONS(448),
    [anon_sym_rspirep] = ACTIONS(448),
    [anon_sym_rsprep] = ACTIONS(448),
    [anon_sym_option] = ACTIONS(448),
    [anon_sym_timeout] = ACTIONS(448),
    [anon_sym_stats] = ACTIONS(448),
    [anon_sym_http_DASHrequest] = ACTIONS(448),
    [anon_sym_http_DASHresponse] = ACTIONS(448),
    [anon_sym_http_DASHcheck] = ACTIONS(448),
    [anon_sym_tcp_DASHrequest] = ACTIONS(448),
    [anon_sym_tcp_DASHresponse] = ACTIONS(448),
    [anon_sym_stick] = ACTIONS(448),
    [anon_sym_stick_DASHtable] = ACTIONS(448),
    [anon_sym_capture] = ACTIONS(448),
    [anon_sym_use_DASHserver] = ACTIONS(448),
    [anon_sym_monitor] = ACTIONS(448),
    [anon_sym_rate_DASHlimit] = ACTIONS(448),
    [anon_sym_persist] = ACTIONS(448),
    [sym_identifier] = ACTIONS(448),
  },
  [28] = {
    [ts_builtin_sym_end] = ACTIONS(450),
    [sym_comment] = ACTIONS(450),
    [anon_sym_global] = ACTIONS(450),
    [anon_sym_defaults] = ACTIONS(450),
    [anon_sym_frontend] = ACTIONS(450),
    [anon_sym_backend] = ACTIONS(450),
    [anon_sym_listen] = ACTIONS(450),
    [anon_sym_peers] = ACTIONS(450),
    [anon_sym_resolvers] = ACTIONS(450),
    [anon_sym_userlist] = ACTIONS(450),
    [anon_sym_aggregations] = ACTIONS(450),
    [anon_sym_acl] = ACTIONS(450),
    [anon_sym_bind] = ACTIONS(452),
    [anon_sym_server] = ACTIONS(450),
    [anon_sym_balance] = ACTIONS(450),
    [anon_sym_mode] = ACTIONS(450),
    [anon_sym_maxconn] = ACTIONS(450),
    [anon_sym_user] = ACTIONS(452),
    [anon_sym_group] = ACTIONS(450),
    [anon_sym_daemon] = ACTIONS(450),
    [anon_sym_log] = ACTIONS(452),
    [anon_sym_retries] = ACTIONS(450),
    [anon_sym_cookie] = ACTIONS(450),
    [anon_sym_errorfile] = ACTIONS(450),
    [anon_sym_default_backend] = ACTIONS(450),
    [anon_sym_use_backend] = ACTIONS(450),
    [anon_sym_compression] = ACTIONS(450),
    [anon_sym_redirect] = ACTIONS(450),
    [anon_sym_source] = ACTIONS(450),
    [anon_sym_id] = ACTIONS(450),
    [anon_sym_disabled] = ACTIONS(450),
    [anon_sym_enabled] = ACTIONS(450),
    [anon_sym_dispatch] = ACTIONS(450),
    [anon_sym_backlog] = ACTIONS(450),
    [anon_sym_description] = ACTIONS(450),
    [anon_sym_chroot] = ACTIONS(450),
    [anon_sym_ca_DASHbase] = ACTIONS(450),
    [anon_sym_crt_DASHbase] = ACTIONS(450),
    [anon_sym_nbproc] = ACTIONS(450),
    [anon_sym_cpu_DASHmap] = ACTIONS(450),
    [anon_sym_lua_DASHload] = ACTIONS(450),
    [anon_sym_monitor_DASHnet] = ACTIONS(450),
    [anon_sym_monitor_DASHuri] = ACTIONS(450),
    [anon_sym_grace] = ACTIONS(450),
    [anon_sym_hash_DASHtype] = ACTIONS(450),
    [anon_sym_force_DASHpersist] = ACTIONS(450),
    [anon_sym_ignore_DASHpersist] = ACTIONS(450),
    [anon_sym_bind_DASHprocess] = ACTIONS(450),
    [anon_sym_default_DASHserver] = ACTIONS(450),
    [anon_sym_log_DASHformat] = ACTIONS(450),
    [anon_sym_unique_DASHid_DASHformat] = ACTIONS(450),
    [anon_sym_unique_DASHid_DASHheader] = ACTIONS(450),
    [anon_sym_nameserver] = ACTIONS(450),
    [anon_sym_peer] = ACTIONS(452),
    [anon_sym_resolution_pool_size] = ACTIONS(450),
    [anon_sym_resolve_retries] = ACTIONS(450),
    [anon_sym_reqadd] = ACTIONS(450),
    [anon_sym_reqallow] = ACTIONS(450),
    [anon_sym_reqdel] = ACTIONS(450),
    [anon_sym_reqdeny] = ACTIONS(450),
    [anon_sym_reqiallow] = ACTIONS(450),
    [anon_sym_reqidel] = ACTIONS(450),
    [anon_sym_reqideny] = ACTIONS(450),
    [anon_sym_reqipass] = ACTIONS(450),
    [anon_sym_reqirep] = ACTIONS(450),
    [anon_sym_reqisetbe] = ACTIONS(450),
    [anon_sym_reqitarpit] = ACTIONS(450),
    [anon_sym_reqpass] = ACTIONS(450),
    [anon_sym_reqrep] = ACTIONS(450),
    [anon_sym_reqsetbe] = ACTIONS(450),
    [anon_sym_reqtarpit] = ACTIONS(450),
    [anon_sym_rspadd] = ACTIONS(450),
    [anon_sym_rspdel] = ACTIONS(450),
    [anon_sym_rspdeny] = ACTIONS(450),
    [anon_sym_rspidel] = ACTIONS(450),
    [anon_sym_rspideny] = ACTIONS(450),
    [anon_sym_rspirep] = ACTIONS(450),
    [anon_sym_rsprep] = ACTIONS(450),
    [anon_sym_option] = ACTIONS(450),
    [anon_sym_timeout] = ACTIONS(450),
    [anon_sym_stats] = ACTIONS(450),
    [anon_sym_http_DASHrequest] = ACTIONS(450),
    [anon_sym_http_DASHresponse] = ACTIONS(450),
    [anon_sym_http_DASHcheck] = ACTIONS(450),
    [anon_sym_tcp_DASHrequest] = ACTIONS(450),
    [anon_sym_tcp_DASHresponse] = ACTIONS(450),
    [anon_sym_stick] = ACTIONS(452),
    [anon_sym_stick_DASHtable] = ACTIONS(450),
    [anon_sym_capture] = ACTIONS(450),
    [anon_sym_use_DASHserver] = ACTIONS(450),
    [anon_sym_monitor] = ACTIONS(452),
    [anon_sym_rate_DASHlimit] = ACTIONS(450),
    [anon_sym_persist] = ACTIONS(450),
  },
};

static const uint16_t ts_small_parse_table[] = {
  [0] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(19), 1,
      sym_option_value,
    ACTIONS(454), 44,
      anon_sym_persist,
      anon_sym_httplog,
      anon_sym_tcplog,
      anon_sym_httpchk,
      anon_sym_forwardfor,
      anon_sym_redispatch,
      anon_sym_abortonclose,
      anon_sym_accept_DASHinvalid_DASHhttp_DASHrequest,
      anon_sym_accept_DASHinvalid_DASHhttp_DASHresponse,
      anon_sym_allbackups,
      anon_sym_checkcache,
      anon_sym_clitcpka,
      anon_sym_contstats,
      anon_sym_dontlog_DASHnormal,
      anon_sym_dontlognull,
      anon_sym_forceclose,
      anon_sym_http_DASHno_DASHdelay,
      anon_sym_http_DASHpretend_DASHkeepalive,
      anon_sym_http_DASHserver_DASHclose,
      anon_sym_http_DASHuse_DASHproxy_DASHheader,
      anon_sym_httpclose,
      anon_sym_http_proxy,
      anon_sym_independent_DASHstreams,
      anon_sym_ldap_DASHcheck,
      anon_sym_log_DASHhealth_DASHchecks,
      anon_sym_log_DASHseparate_DASHerrors,
      anon_sym_logasap,
      anon_sym_mysql_DASHcheck,
      anon_sym_pgsql_DASHcheck,
      anon_sym_nolinger,
      anon_sym_originalto,
      anon_sym_redis_DASHcheck,
      anon_sym_smtpchk,
      anon_sym_socket_DASHstats,
      anon_sym_splice_DASHauto,
      anon_sym_splice_DASHrequest,
      anon_sym_splice_DASHresponse,
      anon_sym_srvtcpka,
      anon_sym_ssl_DASHhello_DASHchk,
      anon_sym_tcp_DASHcheck,
      anon_sym_tcp_DASHsmart_DASHaccept,
      anon_sym_tcp_DASHsmart_DASHconnect,
      anon_sym_tcpka,
      anon_sym_transparent,
  [53] = 8,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(49), 1,
      anon_sym_or,
    STATE(11), 1,
      sym_arguments,
    ACTIONS(51), 2,
      anon_sym_PIPE_PIPE,
      anon_sym_BANG,
    ACTIONS(458), 2,
      sym_number,
      sym_identifier,
    ACTIONS(53), 3,
      anon_sym_if,
      anon_sym_unless,
      anon_sym_rewrite,
    STATE(5), 4,
      sym__argument,
      sym_operator,
      sym_control_flow,
      aux_sym_arguments_repeat1,
    ACTIONS(456), 6,
      sym_string,
      sym_ip_address,
      sym_wildcard_bind,
      sym_time_value,
      sym_parameter,
      sym_path,
  [90] = 8,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(49), 1,
      anon_sym_or,
    STATE(19), 1,
      sym_arguments,
    ACTIONS(51), 2,
      anon_sym_PIPE_PIPE,
      anon_sym_BANG,
    ACTIONS(458), 2,
      sym_number,
      sym_identifier,
    ACTIONS(53), 3,
      anon_sym_if,
      anon_sym_unless,
      anon_sym_rewrite,
    STATE(5), 4,
      sym__argument,
      sym_operator,
      sym_control_flow,
      aux_sym_arguments_repeat1,
    ACTIONS(456), 6,
      sym_string,
      sym_ip_address,
      sym_wildcard_bind,
      sym_time_value,
      sym_parameter,
      sym_path,
  [127] = 8,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(49), 1,
      anon_sym_or,
    STATE(8), 1,
      sym_arguments,
    ACTIONS(51), 2,
      anon_sym_PIPE_PIPE,
      anon_sym_BANG,
    ACTIONS(458), 2,
      sym_number,
      sym_identifier,
    ACTIONS(53), 3,
      anon_sym_if,
      anon_sym_unless,
      anon_sym_rewrite,
    STATE(5), 4,
      sym__argument,
      sym_operator,
      sym_control_flow,
      aux_sym_arguments_repeat1,
    ACTIONS(456), 6,
      sym_string,
      sym_ip_address,
      sym_wildcard_bind,
      sym_time_value,
      sym_parameter,
      sym_path,
  [164] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(19), 1,
      sym_http_action,
    ACTIONS(460), 17,
      anon_sym_redirect,
      anon_sym_auth,
      anon_sym_add_DASHheader,
      anon_sym_set_DASHheader,
      anon_sym_del_DASHheader,
      anon_sym_replace_DASHheader,
      anon_sym_replace_DASHvalue,
      anon_sym_deny,
      anon_sym_allow,
      anon_sym_set_DASHlog_DASHlevel,
      anon_sym_set_DASHnice,
      anon_sym_set_DASHtos,
      anon_sym_set_DASHmark,
      anon_sym_add_DASHacl,
      anon_sym_del_DASHacl,
      anon_sym_set_DASHmap,
      anon_sym_del_DASHmap,
  [190] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(19), 1,
      sym_stats_option,
    ACTIONS(462), 15,
      anon_sym_bind_DASHprocess,
      anon_sym_timeout,
      anon_sym_http_DASHrequest,
      anon_sym_enable,
      anon_sym_uri,
      anon_sym_realm,
      anon_sym_auth,
      anon_sym_refresh,
      anon_sym_admin,
      anon_sym_hide_DASHversion,
      anon_sym_show_DASHdesc,
      anon_sym_show_DASHlegends,
      anon_sym_show_DASHnode,
      anon_sym_socket,
      anon_sym_scope,
  [214] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(19), 1,
      sym_timeout_type,
    ACTIONS(464), 9,
      anon_sym_server,
      anon_sym_http_DASHrequest,
      anon_sym_check,
      anon_sym_client,
      anon_sym_connect,
      anon_sym_http_DASHkeep_DASHalive,
      anon_sym_queue,
      anon_sym_tarpit,
      anon_sym_tunnel,
  [232] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(19), 1,
      sym_stick_option,
    ACTIONS(466), 4,
      anon_sym_match,
      anon_sym_on,
      anon_sym_store_DASHrequest,
      anon_sym_store_DASHresponse,
  [245] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(468), 1,
      anon_sym_cookie,
    STATE(19), 1,
      sym_capture_type,
    ACTIONS(470), 2,
      anon_sym_request,
      anon_sym_response,
  [259] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(19), 1,
      sym_tcp_request_type,
    ACTIONS(472), 3,
      anon_sym_connection,
      anon_sym_content,
      anon_sym_inspect_DASHdelay,
  [271] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(19), 1,
      sym_http_check_option,
    ACTIONS(474), 3,
      anon_sym_disable_DASHon_DASH404,
      anon_sym_expect,
      anon_sym_send_DASHstate,
  [283] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(19), 1,
      sym_tcp_response_type,
    ACTIONS(476), 2,
      anon_sym_content,
      anon_sym_inspect_DASHdelay,
  [294] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(478), 1,
      ts_builtin_sym_end,
  [301] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(480), 1,
      anon_sym_rdp_DASHcookie,
  [308] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(482), 1,
      anon_sym_header,
  [315] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(480), 1,
      anon_sym_sessions,
  [322] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(480), 1,
      anon_sym_fail,
};

static const uint32_t ts_small_parse_table_map[] = {
  [SMALL_STATE(29)] = 0,
  [SMALL_STATE(30)] = 53,
  [SMALL_STATE(31)] = 90,
  [SMALL_STATE(32)] = 127,
  [SMALL_STATE(33)] = 164,
  [SMALL_STATE(34)] = 190,
  [SMALL_STATE(35)] = 214,
  [SMALL_STATE(36)] = 232,
  [SMALL_STATE(37)] = 245,
  [SMALL_STATE(38)] = 259,
  [SMALL_STATE(39)] = 271,
  [SMALL_STATE(40)] = 283,
  [SMALL_STATE(41)] = 294,
  [SMALL_STATE(42)] = 301,
  [SMALL_STATE(43)] = 308,
  [SMALL_STATE(44)] = 315,
  [SMALL_STATE(45)] = 322,
};

static const TSParseActionEntry ts_parse_actions[] = {
  [0] = {.entry = {.count = 0, .reusable = false}},
  [1] = {.entry = {.count = 1, .reusable = false}}, RECOVER(),
  [3] = {.entry = {.count = 1, .reusable = true}}, SHIFT_EXTRA(),
  [5] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_source_file, 0),
  [7] = {.entry = {.count = 1, .reusable = true}}, SHIFT(21),
  [9] = {.entry = {.count = 1, .reusable = true}}, SHIFT(27),
  [11] = {.entry = {.count = 1, .reusable = true}}, SHIFT(17),
  [13] = {.entry = {.count = 1, .reusable = false}}, SHIFT(17),
  [15] = {.entry = {.count = 1, .reusable = true}}, SHIFT(29),
  [17] = {.entry = {.count = 1, .reusable = true}}, SHIFT(35),
  [19] = {.entry = {.count = 1, .reusable = true}}, SHIFT(34),
  [21] = {.entry = {.count = 1, .reusable = true}}, SHIFT(33),
  [23] = {.entry = {.count = 1, .reusable = true}}, SHIFT(39),
  [25] = {.entry = {.count = 1, .reusable = true}}, SHIFT(38),
  [27] = {.entry = {.count = 1, .reusable = true}}, SHIFT(40),
  [29] = {.entry = {.count = 1, .reusable = false}}, SHIFT(36),
  [31] = {.entry = {.count = 1, .reusable = true}}, SHIFT(31),
  [33] = {.entry = {.count = 1, .reusable = true}}, SHIFT(37),
  [35] = {.entry = {.count = 1, .reusable = false}}, SHIFT(45),
  [37] = {.entry = {.count = 1, .reusable = true}}, SHIFT(44),
  [39] = {.entry = {.count = 1, .reusable = true}}, SHIFT(42),
  [41] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_directive, 1, .production_id = 2),
  [43] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_directive, 1, .production_id = 2),
  [45] = {.entry = {.count = 1, .reusable = true}}, SHIFT(3),
  [47] = {.entry = {.count = 1, .reusable = false}}, SHIFT(3),
  [49] = {.entry = {.count = 1, .reusable = false}}, SHIFT(9),
  [51] = {.entry = {.count = 1, .reusable = true}}, SHIFT(9),
  [53] = {.entry = {.count = 1, .reusable = false}}, SHIFT(16),
  [55] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_arguments, 1),
  [57] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_arguments, 1),
  [59] = {.entry = {.count = 1, .reusable = true}}, SHIFT(4),
  [61] = {.entry = {.count = 1, .reusable = false}}, SHIFT(4),
  [63] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_arguments_repeat1, 2),
  [65] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_arguments_repeat1, 2),
  [67] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_arguments_repeat1, 2), SHIFT_REPEAT(4),
  [70] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_arguments_repeat1, 2), SHIFT_REPEAT(4),
  [73] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_arguments_repeat1, 2), SHIFT_REPEAT(9),
  [76] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_arguments_repeat1, 2), SHIFT_REPEAT(9),
  [79] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_arguments_repeat1, 2), SHIFT_REPEAT(16),
  [82] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_arguments, 1), SHIFT(4),
  [85] = {.entry = {.count = 2, .reusable = false}}, REDUCE(sym_arguments, 1), SHIFT(4),
  [88] = {.entry = {.count = 2, .reusable = false}}, REDUCE(sym_arguments, 1), SHIFT(9),
  [91] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_arguments, 1), SHIFT(9),
  [94] = {.entry = {.count = 2, .reusable = false}}, REDUCE(sym_arguments, 1), SHIFT(16),
  [97] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_tcp_response_type, 1),
  [99] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_tcp_response_type, 1),
  [101] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_timeout_type, 1),
  [103] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_timeout_type, 1),
  [105] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_capture_type, 3),
  [107] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_capture_type, 3),
  [109] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_operator, 1),
  [111] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_operator, 1),
  [113] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_tcp_request_type, 1),
  [115] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_tcp_request_type, 1),
  [117] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_capture_type, 2),
  [119] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_capture_type, 2),
  [121] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_http_check_option, 1),
  [123] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_http_check_option, 1),
  [125] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_http_action, 1),
  [127] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_http_action, 1),
  [129] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_stats_option, 1),
  [131] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_stats_option, 1),
  [133] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_stick_option, 1),
  [135] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_stick_option, 1),
  [137] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_control_flow, 1),
  [139] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_control_flow, 1),
  [141] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_keyword, 1),
  [143] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_keyword, 1),
  [145] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_option_value, 1),
  [147] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_option_value, 1),
  [149] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_keyword_combination, 2),
  [151] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_keyword_combination, 2),
  [153] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2),
  [155] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(20),
  [158] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(27),
  [161] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(17),
  [164] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(17),
  [167] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(29),
  [170] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(35),
  [173] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(34),
  [176] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(33),
  [179] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(39),
  [182] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(38),
  [185] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(40),
  [188] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(36),
  [191] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(31),
  [194] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(37),
  [197] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(45),
  [200] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(44),
  [203] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(42),
  [206] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_source_file, 1),
  [208] = {.entry = {.count = 1, .reusable = true}}, SHIFT(20),
  [210] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_section, 1, .production_id = 1),
  [212] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_section, 1, .production_id = 1),
  [214] = {.entry = {.count = 2, .reusable = false}}, REDUCE(sym_section, 1, .production_id = 1), SHIFT(17),
  [217] = {.entry = {.count = 2, .reusable = false}}, REDUCE(sym_section, 1, .production_id = 1), SHIFT(29),
  [220] = {.entry = {.count = 2, .reusable = false}}, REDUCE(sym_section, 1, .production_id = 1), SHIFT(35),
  [223] = {.entry = {.count = 2, .reusable = false}}, REDUCE(sym_section, 1, .production_id = 1), SHIFT(34),
  [226] = {.entry = {.count = 2, .reusable = false}}, REDUCE(sym_section, 1, .production_id = 1), SHIFT(33),
  [229] = {.entry = {.count = 2, .reusable = false}}, REDUCE(sym_section, 1, .production_id = 1), SHIFT(39),
  [232] = {.entry = {.count = 2, .reusable = false}}, REDUCE(sym_section, 1, .production_id = 1), SHIFT(38),
  [235] = {.entry = {.count = 2, .reusable = false}}, REDUCE(sym_section, 1, .production_id = 1), SHIFT(40),
  [238] = {.entry = {.count = 2, .reusable = false}}, REDUCE(sym_section, 1, .production_id = 1), SHIFT(36),
  [241] = {.entry = {.count = 2, .reusable = false}}, REDUCE(sym_section, 1, .production_id = 1), SHIFT(31),
  [244] = {.entry = {.count = 2, .reusable = false}}, REDUCE(sym_section, 1, .production_id = 1), SHIFT(37),
  [247] = {.entry = {.count = 2, .reusable = false}}, REDUCE(sym_section, 1, .production_id = 1), SHIFT(45),
  [250] = {.entry = {.count = 2, .reusable = false}}, REDUCE(sym_section, 1, .production_id = 1), SHIFT(44),
  [253] = {.entry = {.count = 2, .reusable = false}}, REDUCE(sym_section, 1, .production_id = 1), SHIFT(42),
  [256] = {.entry = {.count = 1, .reusable = false}}, SHIFT(24),
  [258] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_section_repeat1, 2),
  [260] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_section_repeat1, 2), SHIFT_REPEAT(17),
  [263] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_section_repeat1, 2), SHIFT_REPEAT(17),
  [266] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_section_repeat1, 2), SHIFT_REPEAT(29),
  [269] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_section_repeat1, 2), SHIFT_REPEAT(35),
  [272] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_section_repeat1, 2), SHIFT_REPEAT(34),
  [275] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_section_repeat1, 2), SHIFT_REPEAT(33),
  [278] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_section_repeat1, 2), SHIFT_REPEAT(39),
  [281] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_section_repeat1, 2), SHIFT_REPEAT(38),
  [284] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_section_repeat1, 2), SHIFT_REPEAT(40),
  [287] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_section_repeat1, 2), SHIFT_REPEAT(36),
  [290] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_section_repeat1, 2), SHIFT_REPEAT(31),
  [293] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_section_repeat1, 2), SHIFT_REPEAT(37),
  [296] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_section_repeat1, 2), SHIFT_REPEAT(45),
  [299] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_section_repeat1, 2), SHIFT_REPEAT(44),
  [302] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_section_repeat1, 2), SHIFT_REPEAT(42),
  [305] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_section, 2, .production_id = 3),
  [307] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 2, .production_id = 3), SHIFT(17),
  [310] = {.entry = {.count = 2, .reusable = false}}, REDUCE(sym_section, 2, .production_id = 3), SHIFT(17),
  [313] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 2, .production_id = 3), SHIFT(29),
  [316] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 2, .production_id = 3), SHIFT(35),
  [319] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 2, .production_id = 3), SHIFT(34),
  [322] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 2, .production_id = 3), SHIFT(33),
  [325] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 2, .production_id = 3), SHIFT(39),
  [328] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 2, .production_id = 3), SHIFT(38),
  [331] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 2, .production_id = 3), SHIFT(40),
  [334] = {.entry = {.count = 2, .reusable = false}}, REDUCE(sym_section, 2, .production_id = 3), SHIFT(36),
  [337] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 2, .production_id = 3), SHIFT(31),
  [340] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 2, .production_id = 3), SHIFT(37),
  [343] = {.entry = {.count = 2, .reusable = false}}, REDUCE(sym_section, 2, .production_id = 3), SHIFT(45),
  [346] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 2, .production_id = 3), SHIFT(44),
  [349] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 2, .production_id = 3), SHIFT(42),
  [352] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_section, 2, .production_id = 1),
  [354] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 2, .production_id = 1), SHIFT(17),
  [357] = {.entry = {.count = 2, .reusable = false}}, REDUCE(sym_section, 2, .production_id = 1), SHIFT(17),
  [360] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 2, .production_id = 1), SHIFT(29),
  [363] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 2, .production_id = 1), SHIFT(35),
  [366] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 2, .production_id = 1), SHIFT(34),
  [369] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 2, .production_id = 1), SHIFT(33),
  [372] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 2, .production_id = 1), SHIFT(39),
  [375] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 2, .production_id = 1), SHIFT(38),
  [378] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 2, .production_id = 1), SHIFT(40),
  [381] = {.entry = {.count = 2, .reusable = false}}, REDUCE(sym_section, 2, .production_id = 1), SHIFT(36),
  [384] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 2, .production_id = 1), SHIFT(31),
  [387] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 2, .production_id = 1), SHIFT(37),
  [390] = {.entry = {.count = 2, .reusable = false}}, REDUCE(sym_section, 2, .production_id = 1), SHIFT(45),
  [393] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 2, .production_id = 1), SHIFT(44),
  [396] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 2, .production_id = 1), SHIFT(42),
  [399] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_section, 3, .production_id = 3),
  [401] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 3, .production_id = 3), SHIFT(17),
  [404] = {.entry = {.count = 2, .reusable = false}}, REDUCE(sym_section, 3, .production_id = 3), SHIFT(17),
  [407] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 3, .production_id = 3), SHIFT(29),
  [410] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 3, .production_id = 3), SHIFT(35),
  [413] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 3, .production_id = 3), SHIFT(34),
  [416] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 3, .production_id = 3), SHIFT(33),
  [419] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 3, .production_id = 3), SHIFT(39),
  [422] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 3, .production_id = 3), SHIFT(38),
  [425] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 3, .production_id = 3), SHIFT(40),
  [428] = {.entry = {.count = 2, .reusable = false}}, REDUCE(sym_section, 3, .production_id = 3), SHIFT(36),
  [431] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 3, .production_id = 3), SHIFT(31),
  [434] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 3, .production_id = 3), SHIFT(37),
  [437] = {.entry = {.count = 2, .reusable = false}}, REDUCE(sym_section, 3, .production_id = 3), SHIFT(45),
  [440] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 3, .production_id = 3), SHIFT(44),
  [443] = {.entry = {.count = 2, .reusable = true}}, REDUCE(sym_section, 3, .production_id = 3), SHIFT(42),
  [446] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_section_name, 1),
  [448] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_section_name, 1),
  [450] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_directive, 2, .production_id = 4),
  [452] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_directive, 2, .production_id = 4),
  [454] = {.entry = {.count = 1, .reusable = true}}, SHIFT(18),
  [456] = {.entry = {.count = 1, .reusable = true}}, SHIFT(5),
  [458] = {.entry = {.count = 1, .reusable = false}}, SHIFT(5),
  [460] = {.entry = {.count = 1, .reusable = true}}, SHIFT(13),
  [462] = {.entry = {.count = 1, .reusable = true}}, SHIFT(14),
  [464] = {.entry = {.count = 1, .reusable = true}}, SHIFT(7),
  [466] = {.entry = {.count = 1, .reusable = true}}, SHIFT(15),
  [468] = {.entry = {.count = 1, .reusable = true}}, SHIFT(30),
  [470] = {.entry = {.count = 1, .reusable = true}}, SHIFT(43),
  [472] = {.entry = {.count = 1, .reusable = true}}, SHIFT(10),
  [474] = {.entry = {.count = 1, .reusable = true}}, SHIFT(12),
  [476] = {.entry = {.count = 1, .reusable = true}}, SHIFT(6),
  [478] = {.entry = {.count = 1, .reusable = true}},  ACCEPT_INPUT(),
  [480] = {.entry = {.count = 1, .reusable = true}}, SHIFT(19),
  [482] = {.entry = {.count = 1, .reusable = true}}, SHIFT(32),
};

#ifdef __cplusplus
extern "C" {
#endif
#ifdef _WIN32
#define extern __declspec(dllexport)
#endif

extern const TSLanguage *tree_sitter_haproxy(void) {
  static const TSLanguage language = {
    .version = LANGUAGE_VERSION,
    .symbol_count = SYMBOL_COUNT,
    .alias_count = ALIAS_COUNT,
    .token_count = TOKEN_COUNT,
    .external_token_count = EXTERNAL_TOKEN_COUNT,
    .state_count = STATE_COUNT,
    .large_state_count = LARGE_STATE_COUNT,
    .production_id_count = PRODUCTION_ID_COUNT,
    .field_count = FIELD_COUNT,
    .max_alias_sequence_length = MAX_ALIAS_SEQUENCE_LENGTH,
    .parse_table = &ts_parse_table[0][0],
    .small_parse_table = ts_small_parse_table,
    .small_parse_table_map = ts_small_parse_table_map,
    .parse_actions = ts_parse_actions,
    .symbol_names = ts_symbol_names,
    .field_names = ts_field_names,
    .field_map_slices = ts_field_map_slices,
    .field_map_entries = ts_field_map_entries,
    .symbol_metadata = ts_symbol_metadata,
    .public_symbol_map = ts_symbol_map,
    .alias_map = ts_non_terminal_alias_map,
    .alias_sequences = &ts_alias_sequences[0][0],
    .lex_modes = ts_lex_modes,
    .lex_fn = ts_lex,
    .primary_state_ids = ts_primary_state_ids,
  };
  return &language;
}
#ifdef __cplusplus
}
#endif
