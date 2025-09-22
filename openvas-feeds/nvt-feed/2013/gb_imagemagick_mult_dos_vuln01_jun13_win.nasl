# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:imagemagick:imagemagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803815");
  script_version("2024-02-28T05:05:37+0000");
  script_cve_id("CVE-2012-0260", "CVE-2012-0259", "CVE-2012-1798");
  script_tag(name:"last_modification", value:"2024-02-28 05:05:37 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-06-24 12:32:12 +0530 (Mon, 24 Jun 2013)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-31 18:42:00 +0000 (Fri, 31 Jul 2020)");
  script_name("ImageMagick < 6.7.6-3 Multiple Denial of Service Vulnerabilities (Jun 2013) - Windows");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2012/q2/19");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52898");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/74659");
  script_xref(name:"URL", value:"http://www.cert.fi/en/reports/2012/vulnerability635606.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_imagemagick_detect_win.nasl");
  script_mandatory_keys("ImageMagick/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation will allow a context-dependent attacker to cause
  denial of service result in loss of availability for the application.");
  script_tag(name:"affected", value:"ImageMagick version before 6.7.6-3 on Windows.");
  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Improper handling of JPEG restart markers of the 'JPEGWarningHandler()'
    function in coders/jpeg.c

  - Improper handling a JPEG EXIF tag of the 'GetEXIFProperty()' function
    in magick/property.c

  - Error occurs when parsing TIFF EXIF IFD of the 'TIFFGetEXIFProperties()'
    function in coders/tiff.c");
  script_tag(name:"solution", value:"Upgrade to ImageMagick version 6.7.6-3 or later.");
  script_tag(name:"summary", value:"ImageMagick is prone to multiple denial of service Vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"6.7.6.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.7.6.3", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
