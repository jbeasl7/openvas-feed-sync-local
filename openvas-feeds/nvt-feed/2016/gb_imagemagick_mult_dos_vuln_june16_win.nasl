# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:imagemagick:imagemagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808068");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2016-4564", "CVE-2016-4562", "CVE-2016-4563");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-09-23 02:00:00 +0000 (Fri, 23 Sep 2016)");
  script_tag(name:"creation_date", value:"2016-06-06 18:38:55 +0530 (Mon, 06 Jun 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("ImageMagick Multiple Denial of Service Vulnerabilities (Jun 2016) - Windows");

  script_tag(name:"summary", value:"ImageMagick is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The DrawDashPolygon function in 'MagickCore/draw.c.' script mishandles
    calculations of certain vertices integer data.

  - The TraceStrokePolygon function in 'MagickCore/draw.c' script mishandles
    the relationship between the BezierQuantum value and certain strokes data.

  - The DrawImage function in 'MagickCore/draw.c' script makes an incorrect
    function call in attempting to locate the next token.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to cause a denial of service (buffer overflow and
  application crash) or possibly have unspecified other impact via
  a crafted file.");

  script_tag(name:"affected", value:"ImageMagick versions before 6.9.4-0
  and 7.x before 7.0.1-2 on Windows.");

  script_tag(name:"solution", value:"Upgrade to ImageMagick version
  6.9.4-0 or 7.0.1-2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.imagemagick.org/script/changelog.php");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/commit/726812fa2fa7ce16bcf58f6e115f65427a1c0950");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_imagemagick_detect_win.nasl");
  script_mandatory_keys("ImageMagick/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!imVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:imVer, test_version:"6.9.4.0"))
{
  fix = "6.9.4-0";
  VULN = TRUE;
}

else if(imVer =~ "^7\.")
{
  if(version_is_less(version:imVer, test_version:"7.0.1.2"))
  {
    fix = "7.0.1-2";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:imVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
