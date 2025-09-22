# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100273");
  script_version("2025-01-22T05:38:11+0000");
  script_tag(name:"last_modification", value:"2025-01-22 05:38:11 +0000 (Wed, 22 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-10-01 18:57:31 +0200 (Thu, 01 Oct 2009)");
  script_cve_id("CVE-2009-3229", "CVE-2009-3230", "CVE-2009-3231");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("PostgreSQL Multiple Security Vulnerabilities (Sep 2009)");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_postgresql_consolidation.nasl");
  script_mandatory_keys("postgresql/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210121192244/http://www.securityfocus.com/bid/36314");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=522085#c1");
  script_xref(name:"URL", value:"http://permalink.gmane.org/gmane.comp.security.oss.general/2088");

  script_tag(name:"summary", value:"PostgreSQL is prone to multiple security vulnerabilities, including a
  denial-of-service issue, a privilege-escalation issue, and an authentication-bypass issue.");

  script_tag(name:"impact", value:"Attackers can exploit these issues to shut down affected servers,
  perform certain actions with elevated privileges, and bypass authentication mechanisms to perform
  unauthorized actions. Other attacks may also be possible.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
loc = infos["location"];

if( version_in_range( version:vers, test_version:"8.4", test_version2:"8.4.0" ) ||
    version_in_range( version:vers, test_version:"8.3", test_version2:"8.3.7" ) ||
    version_in_range( version:vers, test_version:"8.2", test_version2:"8.2.13" ) ||
    version_in_range( version:vers, test_version:"8.1", test_version2:"8.1.17" ) ||
    version_in_range( version:vers, test_version:"8.0", test_version2:"8.0.21" ) ||
    version_in_range( version:vers, test_version:"7.4", test_version2:"7.4.25" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references", install_path:loc );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
