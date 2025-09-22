# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:imagemagick:imagemagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810283");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-10066", "CVE-2016-10067", "CVE-2016-10069");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-07 14:11:00 +0000 (Tue, 07 Mar 2017)");
  script_tag(name:"creation_date", value:"2017-01-16 15:59:02 +0530 (Mon, 16 Jan 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("ImageMagick Multiple Security Bypass And DoS Vulnerabilities - Windows");

  script_tag(name:"summary", value:"ImageMagick is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An improper handling for mat files.

  - Multiple unspecified errors in files 'coders/viff.c' and 'magick/memory.c'");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to cause a denial-of-service condition and bypass certain security
  restrictions to perform unauthorized actions.");

  script_tag(name:"affected", value:"ImageMagick versions before 6.9.4-5
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to ImageMagick version
  6.9.4-5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q4/758");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95216");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95217");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95220");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/commit/8a370f9ab120faf182aa160900ba692ba8e2bcf0");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/commit/0474237508f39c4f783208123431815f1ededb76");
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

if(version_is_less(version:imVer, test_version:"6.9.4.5"))
{
  report = report_fixed_ver(installed_version:imVer, fixed_version:'6.9.4-5');
  security_message(data:report);
  exit(0);
}
