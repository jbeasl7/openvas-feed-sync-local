# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:efrontlearning:efront";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103324");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("eFront <= 3.6.10 build 11944 Multiple XSS Vulnerabilities");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-11-02 08:00:00 +0100 (Wed, 02 Nov 2011)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("secpod_efront_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("efront/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50469");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/520351");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
  to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"eFront 3.6.10 build 11944 is vulnerable. Other versions may also
  be affected.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"eFront is prone to multiple cross-site scripting (XSS)
  vulnerabilities because the software fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + "/index.php?ctg=lesson_info&lessons_ID=2&course=%27%20onmouseover=%27alert(/vt-xss-test/)%27;";

if( http_vuln_check( port:port, url:url, pattern:"' onmouseover='alert\(/vt-xss-test/\)';'>Information for", check_header:TRUE ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
