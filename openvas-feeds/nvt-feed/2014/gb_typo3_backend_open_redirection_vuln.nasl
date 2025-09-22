# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804214");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2010-3661");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-04 18:28:00 +0000 (Mon, 04 Nov 2019)");
  script_tag(name:"creation_date", value:"2014-01-07 19:55:38 +0530 (Tue, 07 Jan 2014)");
  script_name("TYPO3 Backend Open Redirection Vulnerability (TYPO3-SA-2010-012) - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_typo3_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("typo3/http/detected");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-sa-2010-012/");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40742/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42029");

  script_tag(name:"summary", value:"TYPO3 is prone to an open redirect vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"An error exists in the backend which fails to sanitize the
  'redirect' parameter properly.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct
  phishing attacks.");

  script_tag(name:"affected", value:"TYPO3 version prior 4.1.14, 4.2.0 through 4.2.13, 4.3.0 through
  4.3.3 and 4.4.0 only.");

  script_tag(name:"solution", value:"Update to version 4.1.14, 4.2.13, 4.3.4, 4.4.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("url_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("gvr_apps_auth_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

useragent = http_get_user_agent();
host = http_host_name(port:port);
cookie = get_typo3_login_cookie(cinstall:dir, tport:port, chost:host);
if(!cookie)
  exit(0);

url = dir + "/typo3/tce_file.php?redirect=http://www.example.com";

req = string("GET ", url, " HTTP/1.0\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Referer: http://", host, url, "\r\n",
             "Connection: keep-alive\r\n",
             "Cookie: ", cookie, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n\r\n");
res = http_send_recv(port:port, data:req, bodyonly:FALSE);
get_typo3_logout(loc:dir, lport:port, lhost:host, lcookie:cookie);

if(res && res =~ "^HTTP/1\.[01] 302" && "Expires: 0" >< res &&
   "Location: http://www.example.com" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
