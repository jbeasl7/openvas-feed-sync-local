# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153974");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-02-07 03:38:22 +0000 (Fri, 07 Feb 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_name("Allowed HTTP Methods Enumeration");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Enumerates which HTTP methods are allowed.");

  script_tag(name:"vuldetect", value:"Sends multiple HTTP requests and checks the responses.

  Disclaimer:

  - This enumeration script is provided 'as is' (means no support is given) and only providing
  rudimentary information about the possible enabled methods

  - This script doesn't guarantee completeness or full reliability

  For more reliable determination of the enabled HTTP methods please inspect the configuration of
  the web server manually and directly on the target host.");

  script_tag(name:"insight", value: "- Basic HTTP methods: GET, HEAD, POST, PUT, DELETE, CONNECT,
  OPTIONS, TRACE

  - Extended HTTP methods: ACL, BASELINE-CONTROL, BIND, CHECKIN, CHECKOUT, COPY, LABEL, LINK, LOCK,
  MERGE, MKACTIVITY, MKCALENDAR, MKCOL, MKREDIRECTREF, MKWORKSPACE, MOVE, ORDERPATCH, PATCH, PRI,
  PROPFIND, PROPPATCH, REBIND, REPORT, SEARCH, UNBIND, UNCHECKOUT, UNLINK, UNLOCK, UPDATE,
  UPDATEREDIRECTREF, VERSION-CONTROL");

  script_add_preference(name:"Check only basic HTTP methods", type:"radio", value:"yes;no", id:1);
  script_add_preference(name:"Check only '/' URI", type:"radio", value:"yes;no", id:2);
  script_add_preference(name:"Maximum directories to check", type:"entry", value:"30", id:3);

  exit(0);
}

include("http_func.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

base_methods = make_list("GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE");

# https://www.iana.org/assignments/http-methods/http-methods.xhtml#methods
extended_methods = make_list("ACL", "BASELINE-CONTROL", "BIND", "CHECKIN", "CHECKOUT", "COPY",
                             "LABEL", "LINK", "LOCK", "MERGE", "MKACTIVITY", "MKCALENDAR",
                             "MKCOL", "MKREDIRECTREF", "MKWORKSPACE", "MOVE", "ORDERPATCH",
                             "PATCH", "PRI", "PROPFIND", "PROPPATCH", "REBIND", "REPORT",
                             "SEARCH", "UNBIND", "UNCHECKOUT", "UNLINK", "UNLOCK", "UPDATE",
                             "UPDATEREDIRECTREF", "VERSION-CONTROL");

# nb: By default only check the basic HTTP methods
check_basic = script_get_preference("Check only basic HTTP methods", id: 1);
if (check_basic != "no")
  method_list = base_methods;
else
  method_list = make_list(base_methods, extended_methods);

headers = make_array("Content-Length", "0");

vt_strings = get_vt_strings();

req = http_get_req(port: port, url: "/", add_headers: headers);
req = str_replace(string: req, find: "GET", replace: vt_strings["default"]);
res = http_send_recv(port: port, data: req);

error_res = eregmatch(pattern: "^(HTTP/1\.[01] [0-9]+)", string: res);
if (!isnull(error_res[1]))
  error_res = error_res[1];
else
  error_res = "HTTP/1.1 600";

# nb: By default only check the "/" directory.
#     Otherwise check all found directories (time consuming)
check_only_root = script_get_preference("Check only '/' URI", id: 2);
if (check_only_root != "no") {
  dir_list = make_list("/");
  max_dirs = 1;
} else {
  dir_list = make_list_unique("/", http_cgi_dirs(port: port));
  max_dirs = script_get_preference("Maximum directories to check", id: 3);
  if (chomp(max_dirs) == "")
    max_dirs = 30;
}

checked_dirs = 0;

foreach dir (dir_list) {
  found_methods = "";

  if (checked_dirs >= max_dirs)
    break;

  checked_dirs++;

  req = http_get(port: port, item: "/");
  req = str_replace(string: req, find: "GET", replace: "OPTIONS");
  res = http_send_recv(port: port, data: req);

  if (methods = egrep(pattern: "^([Aa]llow|[Pp]ublic)\s*:", string: res, icase: FALSE)) {
    methods = eregmatch(pattern: "^([Aa]llow|[Pp]ublic)\s*:\s*([A-Z,]+\s*([A-Z ,]+)?)", string: methods,
                        icase: FALSE);
    if (!isnull(methods[2])) {
      report_array[http_report_vuln_url(port: port, url: dir, url_only: TRUE)] = chomp(methods[2]) +
                ' (obtained via HTTP OPTIONS method)\n';
      continue;
    }
  }

  foreach method (method_list) {
    req = http_get_req(port: port, url: dir, add_headers: headers);
    req = str_replace(string: req, find: "GET", replace: method);
    res = http_send_recv(port: port, data: req);

    if (!res)
      continue;

    if (res =~ "^HTTP/1\.[01] [1-5][0-9]{2}") {
      # 400: Bad request (mostly an indication that the method is not allowed)
      # 403: Forbidden (might be an indication that the method is not allowed)
      # 405: Method not allowed
      # 406: Not Acceptable ((mostly an indication that the method is not allowed)
      # 501: Unimplemented
      if (res !~ "^HTTP/1\.[01] (40[0356]|501)" && error_res >!< res)
        found_methods += method + ",";
    }
  }

  if (found_methods != "") {
    found_methods = substr(found_methods, 0, strlen(found_methods) - 2);
    report_array[http_report_vuln_url(port: port, url: dir, url_only: TRUE)] = chomp(found_methods);
  }
}

if (report_array) {
  report = "The following list contains the URLs and corresponding supported HTTP methods." +
           '\n\n' +
           text_format_table(array: report_array, sep: " | ", columnheader:make_list("URL", "HTTP Methods"));
  log_message(port: port, data: report);
  exit(0);
}

exit(0);
