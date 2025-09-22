# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113564");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2019-11-14 11:32:42 +0000 (Thu, 14 Nov 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-28 18:29:00 +0000 (Wed, 28 Apr 2021)");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-18853");

  script_name("ImageMagick < 7.0.9-0 Denial of Service (DoS) Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_imagemagick_detect_lin.nasl");
  script_mandatory_keys("ImageMagick/Lin/Ver");

  script_tag(name:"summary", value:"ImageMagick is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability exists because
  XML_PARSE_HUGE is not properly restricted in coders/svg.c.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to exhaust
  the target system's resources.");
  script_tag(name:"affected", value:"ImageMagick through version 7.0.8-68.");
  script_tag(name:"solution", value:"Update to version 7.0.9-0 or later.");

  script_xref(name:"URL", value:"https://fortiguard.com/zeroday/FG-VD-19-136");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/commit/ec9c8944af2bfc65c697ca44f93a727a99b405f1");

  exit(0);
}

CPE = "cpe:/a:imagemagick:imagemagick";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "7.0.9.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.0.9-0", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
