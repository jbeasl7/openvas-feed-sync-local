# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:avast:antivirus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107740");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-24 15:33:00 +0000 (Wed, 24 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-11-01 15:45:00 +0100 (Fri, 01 Nov 2019)");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-11230");

  script_name("Avast Antivirus < 19.4 Link Following Vulnerability - Windows");

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_avast_av_detect_win.nasl", "gb_avast_av_detect_lin.nasl");
  script_mandatory_keys("avast/antivirus/detected");

  script_tag(name:"summary", value:"Avast Antivirus is prone to a link following vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A local administrator can trick the product into renaming arbitrary
  files by replacing the Logs\Update.log file with a symlink. The next time the product attempts to
  write to the log file, the target of the symlink is renamed");

  script_tag(name:"impact", value:"The vulnerability can be exploited to rename a critical product file
  (e.g., AvastSvc.exe), causing the product to fail to start on the next system restart.");

  script_tag(name:"affected", value:"Avast Antivirus prior to version 19.4.");

  script_tag(name:"solution", value:"Update to Avast Antivirus version 19.4 or later.");

  script_xref(name:"URL", value:"http://www.mcerlane.co.uk/CVE-2019-11230");

  exit(0);
}

include( "version_func.inc" );
include( "host_details.inc" );

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"19.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"19.4", install_path:path );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
