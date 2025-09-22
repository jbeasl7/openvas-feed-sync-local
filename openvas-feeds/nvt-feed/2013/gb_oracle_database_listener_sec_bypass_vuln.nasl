# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:database_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803960");
  script_version("2025-09-05T15:40:40+0000");
  script_cve_id("CVE-2000-0818");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-11-06 19:08:11 +0530 (Wed, 06 Nov 2013)");
  script_name("Oracle Database Server listener Security Bypass Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain access to an operating
  system account and execute commands.");

  script_tag(name:"affected", value:"Oracle Database Server versions 7.3.4, 8.0.6, and 8.1.6 are affected.");

  script_tag(name:"insight", value:"A flaw exists in Oracle listener program, which allows attacker to cause
  logging information to be appended to arbitrary files and execute commands via the SET TRC_FILE or SET LOG_FILE commands");

  script_tag(name:"solution", value:"Apply the updates from the referenced advisories.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"summary", value:"Oracle Database Server is prone to a security bypass vulnerability.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1853");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/5380");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("gb_oracle_database_consolidation.nasl");
  script_mandatory_keys("oracle/database/detected");
  script_xref(name:"URL", value:"http://metalink.oracle.com");

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

if(ver =~ "^(8\.[0|1]\.|7\.3\.)") {
  if(version_is_equal(version:ver, test_version:"7.3.4") ||
     version_is_equal(version:ver, test_version:"8.0.6") ||
     version_is_equal(version:ver, test_version:"8.1.6")) {
    report = report_fixed_ver( installed_version:ver, fixed_version:"See references", install_path:path );
    security_message( port:port, data:report );
    exit(0);
  }
}
exit(99);
