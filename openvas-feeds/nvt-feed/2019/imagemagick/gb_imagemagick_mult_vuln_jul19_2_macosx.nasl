# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113459");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2019-08-12 15:58:06 +0000 (Mon, 12 Aug 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-28 18:22:00 +0000 (Wed, 28 Apr 2021)");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-13133", "CVE-2019-13134", "CVE-2019-13135", "CVE-2019-13136", "CVE-2019-13137");

  script_name("ImageMagick <= 7.0.8-49 Multiple Vulnerabilities - Mac OS X");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_imagemagick_detect_macosx.nasl");
  script_mandatory_keys("ImageMagick/MacOSX/Version");

  script_tag(name:"summary", value:"ImageMagick is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Memory leak vulnerability in the function ReadBMPImage in coders/bmp.c

  - Memory leak vulnerability in the function ReadVIFFImage in coders/viff.c

  - Use of uninitialized value vulnerability in the function ReadCUTImage in coders/cut.c

  - Integer overflow vulnerability in the function TIFFSeekCustomStream in coders/tiff.c

  - Memory leak vulnerability in the function ReadPSImage in coders/ps.c");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to crash the application,
  read sensitive information or execute code on the target machine.");
  script_tag(name:"affected", value:"ImageMagick through version 7.0.8-49.");
  script_tag(name:"solution", value:"Update to version 7.0.8-50.");

  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1600");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1599");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1602");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1601");

  exit(0);
}

CPE = "cpe:/a:imagemagick:imagemagick";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "7.0.8.50" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.0.8-50", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
