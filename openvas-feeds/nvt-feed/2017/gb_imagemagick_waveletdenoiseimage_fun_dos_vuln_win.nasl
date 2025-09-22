# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:imagemagick:imagemagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810539");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-9298");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:30:00 +0000 (Sat, 01 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-02-07 16:01:33 +0530 (Tue, 07 Feb 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("ImageMagick 'WaveletDenoiseImage' Function Denial of Service Vulnerability - Windows");

  script_tag(name:"summary", value:"ImageMagick is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to heap overflow error
  in the 'WaveletDenoiseImage' function in MagickCore/fx.c script.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to cause a denial of service (crash) via a crafted image.");

  script_tag(name:"affected", value:"ImageMagick versions before 6.9.6-4 and
  7.x before 7.0.3-6 on Windows.");

  script_tag(name:"solution", value:"Upgrade to ImageMagick version
  6.9.6-4 or 7.0.3-6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/11/14/10");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94310");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2016-9298");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/commit/3cbfb163cff9e5b8cdeace8312e9bfee810ed02b");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("secpod_imagemagick_detect_win.nasl");
  script_mandatory_keys("ImageMagick/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!imVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:imVer, test_version:"6.9.6.4"))
{
  fix = "6.9.6-4";
  VULN = TRUE;
}

else if(imVer =~ "^7\.")
{
  if(version_is_less(version:imVer, test_version:"7.0.3.6"))
  {
    fix = "7.0.3-6";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:imVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(0);
