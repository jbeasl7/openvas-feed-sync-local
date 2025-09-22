# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103032");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-01-14 14:24:22 +0100 (Fri, 14 Jan 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-4172");
  script_name("Apache Tomcat 'sort' and 'orderBy' Parameters XSS Vulnerabilities (Dec 2010/Jan 2011)");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_mandatory_keys("apache/tomcat/detected");

  script_xref(name:"URL", value:"https://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.5");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.30");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/514866");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45015");

  script_tag(name:"summary", value:"Apache Tomcat is prone to multiple cross-site scripting (XSS)
  vulnerabilities because it fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may let the
  attacker steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Apache Tomcat versions 6.0.12 through 6.0.29 and 7.0.0 through
  7.0.4.");

  script_tag(name:"solution", value:"Update to version 6.0.30, 7.0.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"7.0.0", test_version2:"7.0.4" ) ||
    version_in_range( version:vers, test_version:"6.0.12", test_version2:"6.0.29" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.0.30/7.0.5", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
