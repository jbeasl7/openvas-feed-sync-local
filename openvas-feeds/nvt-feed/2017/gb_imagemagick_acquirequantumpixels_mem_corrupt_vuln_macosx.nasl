# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:imagemagick:imagemagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810559");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-8677");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-20 15:29:00 +0000 (Tue, 20 Apr 2021)");
  script_tag(name:"creation_date", value:"2017-02-21 09:24:08 +0530 (Tue, 21 Feb 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("ImageMagick 'AcquireQuantumPixels' Memory Corruption Vulnerability - Mac OS X");

  script_tag(name:"summary", value:"ImageMagick is prone to a memory corruption vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a memory corruption
  error in 'AcquireQuantumPixels' function in MagickCore/quantum.c script.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to have an unspecified impact via a crafted image file,
  which triggers a memory allocation failure.");

  script_tag(name:"affected", value:"ImageMagick version 7.0.3.0 and prior
  on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to ImageMagick version 7.0.3.1 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/10/16/1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93598");
  script_xref(name:"URL", value:"https://blogs.gentoo.org/ago/2016/10/07/imagemagick-memory-allocate-failure-in-acquirequantumpixels-quantum-c");
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

if(version_is_less_equal(version:imVer, test_version:"7.0.3.0"))
{
  report = report_fixed_ver(installed_version:imVer, fixed_version:'7.0.3.1');
  security_message(data:report);
  exit(0);
}
