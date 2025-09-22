# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dropbear_ssh_project:dropbear_ssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112870");
  script_version("2025-09-02T05:39:48+0000");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-02 05:39:48 +0000 (Tue, 02 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-02 19:09:00 +0000 (Tue, 02 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-03 13:57:11 +0000 (Wed, 03 Mar 2021)");

  script_cve_id("CVE-2020-36254");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dropbear < 2020.79 Mishandling Filenames Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_dropbear_consolidation.nasl");
  script_mandatory_keys("dropbear_ssh/detected");

  script_tag(name:"summary", value:"Dropbear is mishandling the filename of . or an empty
  filename.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This is a follow-up fix for CVE-2018-20685 which allowed an
  attacker to modify the name of output files.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to modify the
  permissions of the target directory on the client side.");

  script_tag(name:"affected", value:"Dropbear prior to version 2020.79.");

  script_tag(name:"solution", value:"Update to version 2020.79 or later.");

  script_xref(name:"URL", value:"https://github.com/mkj/dropbear/commit/8f8a3dff705fad774a10864a2e3dbcfa9779ceff");
  script_xref(name:"URL", value:"https://matt.ucc.asn.au/dropbear/CHANGES");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"2020.79" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2020.79", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
