# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111014");
  script_version("2025-04-11T15:45:04+0000");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2015-04-15 07:00:00 +0100 (Wed, 15 Apr 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2007-1355");
  script_name("Apache Tomcat JSP Example Web Applications XSS Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/tomcat/http/detected");

  script_xref(name:"URL", value:"https://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.11");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-5.html#Fixed_in_Apache_Tomcat_5.5.24,_5.0.SVN");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-4.html#Fixed_in_Apache_Tomcat_4.1.37");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/24476");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Exploiting this vulnerability may allow an attacker to perform
  XSS attacks on unsuspecting users in the context of the affected website. As a result, the
  attacker may be able to steal cookie-based authentication credentials and to launch other
  attacks.");

  script_tag(name:"affected", value:"Apache Tomcat versions 4.0.1 through 4.0.6, 4.1.0 through
  4.1.36, 5.0.0 through 5.0.30, 5.5.0 through 5.5.23 and 6.0.0 through 6.0.10.");

  script_tag(name:"solution", value:"Update to version 4.1.37, 5.5.24, 6.0.11 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = "/jsp-examples/snp/snoop.jsp;test<script>alert('attack');</script>";

if( http_vuln_check( port:port, url:url, pattern:"<script>alert\('attack'\);</script>", extra_check:"test", check_header:TRUE ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
