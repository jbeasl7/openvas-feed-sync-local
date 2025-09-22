# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:database_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802519");
  script_version("2024-10-29T05:05:45+0000");
  script_cve_id("CVE-2007-2113", "CVE-2007-2118");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-10-29 05:05:45 +0000 (Tue, 29 Oct 2024)");
  script_tag(name:"creation_date", value:"2011-12-01 17:11:26 +0530 (Thu, 01 Dec 2011)");
  script_name("Oracle Database Server Upgrade and Downgrade Component Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_oracle_database_consolidation.nasl");
  script_mandatory_keys("oracle/database/detected");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1017927");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23532");
  script_xref(name:"URL", value:"http://www.us-cert.gov/cas/techalerts/TA07-108A.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/466153/100/0/threaded");
  script_xref(name:"URL", value:"http://www.red-database-security.com/advisory/oracle_sql_injection_dbms_upgrade_internal.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2007-090632.html");

  script_tag(name:"impact", value:"Successful exploitation allows remote authenticated users to
  execute arbitrary SQL commands via unknown vectors.");

  script_tag(name:"affected", value:"Oracle Database Server versions 9.0.1.5, 9.2.0.7 and
  10.1.0.5.");

  script_tag(name:"insight", value:"The flaw is due to an error in the Upgrade/Downgrade
  component.");

  script_tag(name:"summary", value:"Oracle Database Server is prone to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

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

if( version_in_range( version:vers, test_version:"10.1.0", test_version2:"10.1.0.4" ) ||
    version_in_range( version:vers, test_version:"9.0.1", test_version2:"9.0.1.4" ) ||
    version_in_range( version:vers, test_version:"9.2.0", test_version2:"9.2.0.6" ) ||
    version_is_equal( version:vers, test_version:"9.0.1.5" ) ||
    version_is_equal( version:vers, test_version:"9.2.0.7" ) ||
    version_is_equal( version:vers, test_version:"10.1.0.5" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
