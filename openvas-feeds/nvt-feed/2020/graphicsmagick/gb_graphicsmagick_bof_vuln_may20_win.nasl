# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113686");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2020-05-11 10:40:42 +0000 (Mon, 11 May 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-10 18:15:00 +0000 (Wed, 10 Jun 2020)");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-12672");

  script_name("GraphicsMagick <= 1.3.35 Buffer Overflow Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("os_detection.nasl", "gb_graphicsmagick_detect_win.nasl");
  script_mandatory_keys("Host/runs_windows", "GraphicsMagick/Win/Installed");

  script_tag(name:"summary", value:"GraphicsMagick is prone to heap-based buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability resides within ReadMNGImage in coders/png.c.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to crash the application.");

  script_tag(name:"affected", value:"GraphicsMagick through version 1.3.35.");

  script_tag(name:"solution", value:"Update to version 1.3.36 or later.");

  script_xref(name:"URL", value:"https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=19025");
  script_xref(name:"URL", value:"https://sourceforge.net/projects/graphicsmagick/files/");

  exit(0);
}

CPE = "cpe:/a:graphicsmagick:graphicsmagick";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "1.3.35" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.3.36", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
