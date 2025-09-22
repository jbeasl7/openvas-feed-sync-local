# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:imagemagick:imagemagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810254");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-5841", "CVE-2016-5842");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-15 03:02:00 +0000 (Thu, 15 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-06-06 18:38:55 +0530 (Mon, 06 Jun 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("ImageMagick Information Disclosure And Denial Of Service Vulnerabilities - Mac OS X");

  script_tag(name:"summary", value:"ImageMagick is prone to information disclosure and denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An integer overflow error in 'MagickCore/profile.c' script.

  - An out-of-bounds read error in 'MagickCore/property.c' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to obtain sensitive memory information and cause a denial of
  service (segmentation fault) or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"ImageMagick versions before 7.0.2-1 on
  Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to ImageMagick version
  7.0.2-1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/06/23/1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91394");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/commits/7.0.2-1");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/06/25/3");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/commit/d8ab7f046587f2e9f734b687ba7e6e10147c294b");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18841");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_imagemagick_detect_macosx.nasl");
  script_mandatory_keys("ImageMagick/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!imVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:imVer, test_version:"7.0.2.1"))
{
  report = report_fixed_ver(installed_version:imVer, fixed_version:"7.0.2-1");
  security_message(data:report);
  exit(0);
}
