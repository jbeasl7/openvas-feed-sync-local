# SPDX-FileCopyrightText: 2003 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oscommerce:oscommerce";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11958");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2003-1219");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("osCommerce Malformed Session ID XSS Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2003 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("gb_oscommerce_http_detect.nasl");
  script_mandatory_keys("oscommerce/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"solution", value:"Update to osCommerce 2.2 Milestone 3 or later which will
  redirect the user to the index page when a malformed session ID is used, so that a new session
  ID can be generated.");

  script_tag(name:"summary", value:"osCommerce is vulnerable to an XSS flaw. The flaw can be
  exploited when a malicious user passes a malformed session ID to URI.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

quote = raw_string(0x22);

url = string(dir, "?osCsid=%22%3E%3Ciframe%20src=foo%3E%3C/iframe%3E");
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if(!res)
  exit(0);

find = string("\\?osCsid=", quote, "><iframe src=foo></iframe>");
if(egrep(pattern:find, string:res) && ("Powered by" >< res) && ("osCommerce" >< res)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
