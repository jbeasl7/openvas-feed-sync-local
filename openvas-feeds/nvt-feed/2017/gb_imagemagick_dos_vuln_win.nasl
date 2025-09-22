# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:imagemagick:imagemagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107206");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-05-23 19:30:51 +0200 (Tue, 23 May 2017)");
  script_cve_id("CVE-2017-9144");

  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 16:12:00 +0000 (Thu, 15 Oct 2020)");

  script_tag(name:"qod_type", value:"registry");
  script_name("ImageMagick coders/rle.c Denial of Service Vulnerability - Windows");

  script_tag(name:"summary", value:"ImageMagick is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to crash the affected application, resulting in denial-of-service conditions.");

  script_tag(name:"affected", value:"ImageMagick versions prior to 6.9.8-5 and 7.0.x prior to 7.0.5-6.");

  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory for more information.");

  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/blob/master/ChangeLog");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98603");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/blob/ImageMagick-6/ChangeLog");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/commit/7fdf9ea808caa3c81a0eb42656e5fafc59084198");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");

  script_family("Denial of Service");
  script_dependencies("secpod_imagemagick_detect_win.nasl");
  script_mandatory_keys("ImageMagick/Win/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"6.9.8.5" ) ) {
  vuln = TRUE;
  fix = "6.9.8-5";
}

if ( version_in_range( version:vers, test_version:"7.0.0", test_version2:"7.0.5.5" ) ) {
  vuln = TRUE;
  fix = "7.0.5-6";
}

if ( vuln ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit ( 99 );

