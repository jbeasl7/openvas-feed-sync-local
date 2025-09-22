# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:database_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804227");
  script_version("2025-09-05T15:40:40+0000");
  script_cve_id("CVE-2013-5764", "CVE-2013-5853");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2014-01-24 14:49:13 +0530 (Fri, 24 Jan 2014)");
  script_name("Oracle Database Server Multiple Unspecified Vulnerabilities-01 (Jan 2014)");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_mandatory_keys("oracle/database/detected");
  script_dependencies("gb_oracle_database_consolidation.nasl");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56452/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64811");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64817");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html");

  script_tag(name:"summary", value:"Oracle Database Server is prone to multiple information disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist in Core RDBMS component component, no further
  information available at this moment.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause denial of service
  condition.");

  script_tag(name:"affected", value:"Oracle Database Server version 11.1.0.7, 11.2.0.3, and 12.1.0.1
  are affected");

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

ver = infos["version"];
path = infos["location"];

if(ver =~ "^(11\.[1|2]\.0|12\.1\.0)") {
  if(version_is_equal(version:ver, test_version:"11.2.0.3") ||
     version_is_equal(version:ver, test_version:"12.1.0.1") ||
     version_is_equal(version:ver, test_version:"11.1.0.7")) {
    report = report_fixed_ver(installed_version:ver, fixed_version:"See references for available updates.", install_path:path);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
