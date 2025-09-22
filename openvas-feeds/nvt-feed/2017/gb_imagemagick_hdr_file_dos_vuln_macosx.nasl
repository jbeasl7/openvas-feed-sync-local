# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:imagemagick:imagemagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810583");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2015-8900");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-31 11:39:00 +0000 (Fri, 31 Jul 2020)");
  script_tag(name:"creation_date", value:"2017-03-09 12:46:30 +0530 (Thu, 09 Mar 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("ImageMagick HDR File Processing Denial of Service Vulnerability - Mac OS X");

  script_tag(name:"summary", value:"ImageMagick is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an HDR file processing
  error in the 'ReadHDRImage' function in 'coders/hdr.c' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to cause a denial of service condition.");

  script_tag(name:"affected", value:"ImageMagick versions 6.x before
  6.9.0-5 Beta on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to ImageMagick version
  6.9.0-5 Beta or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/02/26/13");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1195260");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_imagemagick_detect_macosx.nasl");
  script_mandatory_keys("ImageMagick/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!imVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(imVer =~ "^6\.")
{
  if(version_in_range(version:imVer, test_version: "6.0", test_version2: "6.9.0.4"))
  {
    report = report_fixed_ver(installed_version:imVer, fixed_version:'6.9.0-5 Beta');
    security_message(data:report);
    exit(0);
  }
}

exit( 0 );