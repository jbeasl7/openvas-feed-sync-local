# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


CPE = "cpe:/a:qnap:video_station";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170097");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2022-05-09 09:08:13 +0000 (Mon, 09 May 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-13 20:14:00 +0000 (Fri, 13 May 2022)");

  script_cve_id("CVE-2021-44055", "CVE-2021-44056");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Video Station Multiple Vulnerabilities (QSA-22-14)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_videostation_http_detect.nasl");
  script_mandatory_keys("qnap/videostation/detected");

  script_tag(name:"summary", value:"QNAP Video Station is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"If exploited, this vulnerability allows remote attackers to access
  sensitive data, perform unauthorized actions, and compromise the security of the system.");

  script_tag(name:"affected", value:"QNAP Video Station versions prior to 5.1.8, 5.2.x through 5.3.12,
  5.4 through 5.5.8.");

  script_tag(name:"solution", value:"Update to version 5.1.8, 5.3.13, 5.5.9 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en-au/security-advisory/qsa-22-14");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_is_less( version:version, test_version:"5.1.8" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.1.8", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range( version:version, test_version:"5.2.0", test_version2:"5.3.12" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.3.13", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range( version:version, test_version:"5.4.0", test_version2:"5.5.8" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.5.9", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
