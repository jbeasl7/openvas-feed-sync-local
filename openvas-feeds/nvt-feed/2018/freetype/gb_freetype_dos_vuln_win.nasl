# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113115");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2018-02-16 12:00:00 +0100 (Fri, 16 Feb 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-26 12:33:00 +0000 (Tue, 26 Jan 2021)");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-6942");

  script_name("FreeType 2.x < 2.9.1 DoS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_freetype_detect_win.nasl");
  script_mandatory_keys("FreeType/Win/Ver");

  script_tag(name:"summary", value:"FreeType 2 is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in FreeType 2. A NULL pointer
  dereference in the Ins_GETVARIATION() function within ttinterp.c could lead to DoS via a crafted
  font file.");

  script_tag(name:"affected", value:"FreeType 2 through version 2.9.");

  script_tag(name:"solution", value:"Update to version 2.9.1 or later.");

  script_xref(name:"URL", value:"https://git.savannah.gnu.org/cgit/freetype/freetype2.git/commit/?id=29c759284e305ec428703c9a5831d0b1fc3497ef");
  script_xref(name:"URL", value:"https://download.savannah.gnu.org/releases/freetype/");
  script_xref(name:"URL", value:"https://sourceforge.net/projects/freetype/files/freetype2/2.9.1/");

  exit(0);
}

CPE = "cpe:/a:freetype:freetype";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE ) ) exit( 0 );

if( version_in_range( version: version, test_version: "2.0.0.0", test_version2: "2.9.0.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.9.1" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
