# SPDX-FileCopyrightText: 2001 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10766");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2001-1013");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Apache HTTP Server UserDir Sensitive Information Disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 SecuriTeam");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/http_server/http/detected");

  script_xref(name:"URL", value:"http://www.securiteam.com/unixfocus/5WP0C1F5FI.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3335");

  script_tag(name:"solution", value:"1) Disable this feature by changing 'UserDir public_html' (or whatever) to
  'UserDir  disabled'.

  Or

  2) Use a RedirectMatch rewrite rule under Apache -- this works even if there
  is no such  entry in the password file, e.g.:
  RedirectMatch ^/~(.*)$ http://example.com/$1

  Or

  3) Add into httpd.conf:

  ErrorDocument 404 http://example.com/sample.html

  ErrorDocument 403 http://example.com/sample.html

  (NOTE: You need to use a FQDN inside the URL for it to work properly).");

  script_tag(name:"summary", value:"An information leak occurs on Apache HTTP Server based
  web servers whenever the UserDir module is enabled. The vulnerability allows an external
  attacker to enumerate existing accounts by requesting access to their home directory
  and monitoring the response.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

req = http_head(item:"/~root", port:port);
buf_valid = http_send_recv(port:port, data:req);

req = http_head(item:"/~anna_foo_fighter", port:port);
buf_invalid = http_send_recv(port:port, data:req);

if(buf_valid =~ "^HTTP/1\.[01] 403" && buf_invalid =~ "^HTTP/1\.[01] 404") {
  security_message(port:port);
  exit(0);
}

exit(99);
