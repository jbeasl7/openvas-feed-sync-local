# SPDX-FileCopyrightText: 2005 Josh Zlatin-Amishav
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:woltlab:burning_board"; # nb: JGS-Portal is running on Woltlab BB

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18289");
  script_version("2024-05-08T05:05:32+0000");
  script_cve_id("CVE-2005-1633", "CVE-2005-1634", "CVE-2005-1635");
  script_tag(name:"last_modification", value:"2024-05-08 05:05:32 +0000 (Wed, 08 May 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("JGS-XA JGS-Portal <= 3.0.2 Multiple XSS and SQLi Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
  script_dependencies("secpod_woltlab_burning_board_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("WoltLabBurningBoard/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210206163514/http://www.securityfocus.com/bid/13650/");

  script_tag(name:"summary", value:"The remote version of JGS-Portal contains an input validation
  flaw leading multiple SQL injection and XSS vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker may exploit these flaws to execute arbitrary SQL
  commands against the remote database and to cause arbitrary code execution for third party users.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/jgs_portal_statistik.php?meinaction=themen&month=1&year=1'";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(!res)
  exit(0);

if("SQL-DATABASE ERROR" >< res && "SELECT starttime FROM bb1_threads WHERE FROM_UNIXTIME" >< res ) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
