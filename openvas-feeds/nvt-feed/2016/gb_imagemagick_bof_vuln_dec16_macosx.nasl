# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:imagemagick:imagemagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810253");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-6491");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:30:00 +0000 (Sat, 01 Jul 2017)");
  script_tag(name:"creation_date", value:"2016-06-06 18:38:55 +0530 (Mon, 06 Jun 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("ImageMagick 'Get8BIMProperty' Buffer Overflow Vulnerability - Mac OS X");

  script_tag(name:"summary", value:"ImageMagick is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a buffer overflow error
  in the Get8BIMProperty function in 'MagickCore/property.c' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service.");

  script_tag(name:"affected", value:"ImageMagick versions before 6.9.5-4 and 7.x
  before 7.0.2-6 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to ImageMagick version
  6.9.5-4 or 7.0.2-6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1036501");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92186");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q3/192");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/07/28/13");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("gb_imagemagick_detect_macosx.nasl");
  script_mandatory_keys("ImageMagick/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!imVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:imVer, test_version:"6.9.5.4"))
{
  fix = "6.9.5-4";
  VULN = TRUE;
}

else if(imVer =~ "^7\.")
{
  if(version_is_less(version:imVer, test_version:"7.0.2.6"))
  {
    fix = "7.0.2-6";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:imVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

