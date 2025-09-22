# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100645");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-05-19 12:58:40 +0200 (Wed, 19 May 2010)");
  script_cve_id("CVE-2010-1169", "CVE-2010-1170", "CVE-2010-1447");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_name("PostgreSQL Multiple Security Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_postgresql_consolidation.nasl");
  script_mandatory_keys("postgresql/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40215");
  script_xref(name:"URL", value:"http://www.postgresql.org/about/news.1203");

  script_tag(name:"summary", value:"PostgreSQL is prone to multiple security vulnerabilities.");

  script_tag(name:"impact", value:"Attackers can exploit these issues to bypass certain security
  restrictions and execute arbitrary Perl or Tcl code.");

  script_tag(name:"affected", value:"These issues affect versions prior to the following PostgreSQL
  versions:

  8.4.4, 8.3.11, 8.2.17, 8.1.21, 8.0.25, 7.4.29.");

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

if( version_in_range( version:vers, test_version:"8.4", test_version2:"8.4.3" ) ||
    version_in_range( version:vers, test_version:"8.3", test_version2:"8.3.10" ) ||
    version_in_range( version:vers, test_version:"8.2", test_version2:"8.2.16" ) ||
    version_in_range( version:vers, test_version:"8.1", test_version2:"8.1.20" ) ||
    version_in_range( version:vers, test_version:"8.0", test_version2:"8.0.24" ) ||
    version_in_range( version:vers, test_version:"7.4", test_version2:"7.4.28" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references", install_path:loc );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
