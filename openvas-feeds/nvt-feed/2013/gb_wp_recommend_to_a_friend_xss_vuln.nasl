# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804048");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2013-7276");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2013-12-30 18:18:36 +0530 (Mon, 30 Dec 2013)");
  script_name("WordPress Recommend to a friend Plugin <= 2.0.2 XSS Vulnerability");

  script_tag(name:"summary", value:"The WordPress plugin 'Recommend to a friend' is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.");
  script_tag(name:"solution", value:"Updates are available.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"insight", value:"Flaw is due to an improper validation of user supplied input to the
'current_url' parameter in 'raf_form.php' script.");
  script_tag(name:"affected", value:"WordPress Recommend to a friend Plugin version 2.0.2, Other versions may
also be affected.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site.");
  script_xref(name:"URL", value:"http://secunia.com/advisories/56209");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64548");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56209");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013120161");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/wordpress-recommend-cross-site-scripting");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);
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

url = dir + '/wp-content/plugins/recommend-a-friend/inc/raf_form.php'+
            '?current_url="/><script>alert(document.cookie);</script>';

if(http_vuln_check(port:port, url:url, check_header:TRUE,
                   pattern:"<script>alert\(document\.cookie\);</script>",
                   extra_check:">Recommend this page"))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}
