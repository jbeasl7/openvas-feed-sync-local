# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:setseed:setseed_cms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103327");
  script_version("2025-07-23T05:44:58+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-07-23 05:44:58 +0000 (Wed, 23 Jul 2025)");
  script_tag(name:"creation_date", value:"2011-11-03 08:00:00 +0100 (Thu, 03 Nov 2011)");
  script_cve_id("CVE-2011-5116");
  script_name("SetSeed CMS 5.8.20 'loggedInUser' SQLi Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_setseed_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("setseed/http/detected");

  script_xref(name:"URL", value:"https://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-5053.php");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/18065");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210126233718/http://www.securityfocus.com/bid/50498");

  script_tag(name:"summary", value:"SetSeed CMS is prone to an SQL injection (SQLi) vulnerability
  because it fails to sufficiently sanitize user-supplied data before using it in an SQL query.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying database
  implementation.");

  script_tag(name:"affected", value:"SetSeed CMS version 5.8.20 is known to be vulnerable. Other
  versions may also be affected.");

  script_tag(name:"solution", value:"Update to version 5.11.2 or later.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"VendorFix");

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

host = http_host_name(port:port);

url = dir + "/";
# nb: No http_get_cache() to "grab" a fresh cookie...
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

session_id = eregmatch(pattern:"[Ss]et-[Cc]ookie\s*:\s*([^;]*);", string:res);
if(isnull(session_id[1]))
  exit(0);

sess = session_id[1];
url = dir + "/setseed-hub/";

req = string(
  "GET ", url, " HTTP/1.1\r\n",
  "Cookie: loggedInKey=PYNS9QVWLEBG1E7C9UFCT674DYNW9YJ; loggedInUser=1%27; ", sess, "\r\n",
  "Host: ", host, "\r\n",
  "Connection: Keep-alive\r\n",
  "\r\n\r\n");
res = http_keepalive_send_recv(port:port, data:req);

if("You have an error in your SQL syntax" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
