# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100068");
  script_version("2024-03-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-03-21 10:04:15 +0100 (Sat, 21 Mar 2009)");
  script_cve_id("CVE-2006-6942");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("phpMyAdmin Multiple Input Validation Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_phpmyadmin_http_detect.nasl");
  script_mandatory_keys("phpMyAdmin/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/21137");

  script_tag(name:"summary", value:"phpMyAdmin is prone to multiple input-validation vulnerabilities,
  including an HTML-injection vulnerability, cross-site scripting vulnerabilities, and information-disclosure
  vulnerabilities.");

  script_tag(name:"impact", value:"An attacker could exploit these vulnerabilities to view sensitive
  information or to have arbitrary script code execute in the context of the affected site, which may
  allow the attacker to steal cookie-based authentication credentials or change the way the site
  is rendered to the user. Data gained could aid in further attacks.");

  script_tag(name:"solution", value:"Update to version 2.9.1.1 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"2.9.1.1") ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.9.1.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
