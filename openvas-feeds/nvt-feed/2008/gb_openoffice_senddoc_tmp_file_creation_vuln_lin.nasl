# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openoffice:openoffice.org";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800129");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-11-11 09:00:11 +0100 (Tue, 11 Nov 2008)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2008-4937");
  script_name("OpenOffice.org <= 2.4.1 senddoc Insecure Temporary File Creation Vulnerability - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openoffice_ssh_login_detect.nasl");
  script_mandatory_keys("openoffice.org/linux/detected");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2008/10/30/2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30925");

  script_tag(name:"summary", value:"OpenOffice.org is prone to an insecure temporary file creation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to OpenOffice 'senddoc' which creates
  temporary files in an insecure manner, which allows users to overwrite files via a symlink attack
  on a /tmp/log.obr.##### temporary file.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to delete or corrupt
  sensitive files, which may result in a denial of service condition.");

  script_tag(name:"affected", value:"OpenOffice.org 2.4.1 and prior.");

  script_tag(name:"solution", value:"Update to the latest OpenOffice.org version.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) )
  exit( 0 );

if( version_is_less_equal( version:version, test_version:"2.4.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"See references" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
