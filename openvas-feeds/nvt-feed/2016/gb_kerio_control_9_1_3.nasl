# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:kerio:control";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140068");
  script_version("2025-01-22T05:38:11+0000");
  script_tag(name:"last_modification", value:"2025-01-22 05:38:11 +0000 (Wed, 22 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-11-17 12:58:24 +0100 (Thu, 17 Nov 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Kerio Control < 9.1.3 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_kerio_control_consolidation.nasl");
  script_mandatory_keys("kerio/control/http/detected");
  script_require_ports("Services/www", 4081);

  script_tag(name:"summary", value:"Kerio Control is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Unsafe usage of the PHP unserialize function and outdated PHP version leads to remote code
  execution (RCE)

  - PHP script allows heap spraying

  - CSRF protection bypass

  - Reflected cross-site scripting (XSS)

  - Missing memory corruption protections

  - Information disclosure leads to ASLR bypass

  - Remote code execution (RCE) as administrator

  - Login not protected against brute-force attacks

  See the referenced advisory for further information.");

  script_tag(name:"affected", value:"Kerio Control prior to version 9.1.3.");

  script_tag(name:"solution", value:"Update to version 9.1.3 or later.");

  script_xref(name:"URL", value:"https://sec-consult.com/vulnerability-lab/advisory/potential-backdoor-access-through-multiple-vulnerabilities/");
  script_xref(name:"URL", value:"https://sec-consult.com/blog/detail/controlling-kerio-control-when-your-firewall-turns-against-you/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = "/admin/internal/dologin.php?hash=%0D%0A%22%3E%3Cscript%3Ealert(/vt-xss-test/);%3C/script%3E%3C!--";

if( http_vuln_check( port:port, url:url, pattern:'"><script>alert\\(/vt-xss-test/\\);</script><!--</a>',
                     extra_check:make_list( "^HTTP/1\.[01] 302" ), check_nomatch:make_list( "^Location\s*:" ) ) ) {
  report = http_report_vuln_url( port:port, url:url);
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
