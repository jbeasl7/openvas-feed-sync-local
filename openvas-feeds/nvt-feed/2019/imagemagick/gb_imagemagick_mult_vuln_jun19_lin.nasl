# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113420");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2019-07-01 15:08:10 +0000 (Mon, 01 Jul 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-19 18:59:00 +0000 (Wed, 19 Aug 2020)");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-12974", "CVE-2019-12975", "CVE-2019-12976", "CVE-2019-12977", "CVE-2019-12978", "CVE-2019-12979");

  script_name("ImageMagick <= 7.0.8-34 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_imagemagick_detect_lin.nasl");
  script_mandatory_keys("ImageMagick/Lin/Ver");

  script_tag(name:"summary", value:"ImageMagick is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - A NULL pointer dereference in the function ReadPANGOImage in coders/pango.c and
    the function ReadVIDImage in coders/vid.c allows remote attackers to cause
    a denial of service via a crafted image.

  - There is a memory leak vulnerability in the WripteDPXImage function in coders/dpx.c.

  - There is a memory leak in the ReadPCLImage function in coders/pcl.c.

  - There is a 'use of uninitialized value' vulnerability in the
    WriteJP2Image function in coders/jp2.c.

  - There is a 'use of uninitialized value' vulnerability in the
    ReadPANGOImage function in coders/pango.c.

  - There is a 'use of uninitialized value' vulnerability in the SyncImageSettings function
    in MagickCore/image.c. This is related to AcquireImage in magick/image.c.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to crash the application,
  access sensitive information or even execute arbitrary code on the target machine.");
  script_tag(name:"affected", value:"ImageMagick through version 7.0.8-34.");
  script_tag(name:"solution", value:"Update to version 7.0.8-35.");

  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1515");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/108913");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1517");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1518");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1519");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1520");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1522");

  exit(0);
}

CPE = "cpe:/a:imagemagick:imagemagick";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "7.0.8.35" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.0.8-35", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
