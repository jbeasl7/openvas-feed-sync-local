# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103033");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"creation_date", value:"2011-01-19 13:37:44 +0100 (Wed, 19 Jan 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("CompactCMS <= 1.4.1 Multiple XSS Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "cross_site_scripting.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"CompactCMS is prone to multiple cross-site scripting (XSS)
  vulnerabilities because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Attacker-supplied script code may be executed in the context of
  the affected site, potentially allowing the attacker to steal cookie-based authentication
  credentials.");

  script_tag(name:"affected", value:"CompactCMS version 1.4.1 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45819");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

host = http_host_name(dont_add_port: TRUE);
if (http_get_has_generic_xss(port: port, host: host))
  exit(0);

vt_strings = get_vt_strings();

foreach dir (make_list_unique("/compactcms", "/ccms", "/cms", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/afdrukken.php");
  if (!res || res !~ "^HTTP/1\.[01] 200")
    continue;

  url = dir + "/afdrukken.php?page=%22%3E%3Cscript%3Ealert(%27" + vt_strings["lowercase"] +
        "%27)%3C/script%3E";

  if (http_vuln_check(port: port, url: url, pattern:"<script>alert\('" + vt_strings["lowercase"] +
                      "'\)</script>", check_header: TRUE)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
