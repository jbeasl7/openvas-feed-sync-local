# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:graphicsmagick:graphicsmagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810560");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2016-7446", "CVE-2016-7447", "CVE-2016-7448", "CVE-2016-7449");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-15 14:03:00 +0000 (Mon, 15 Apr 2019)");
  script_tag(name:"creation_date", value:"2017-02-21 10:39:33 +0530 (Tue, 21 Feb 2017)");
  script_name("GraphicsMagick Multiple Vulnerabilities-01 (Feb 2017) - Windows");

  script_tag(name:"summary", value:"GraphicsMagick is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as,

  - The TIFF reader had a bug pertaining to use of 'TIFFGetField' function when
    a 'count' value is returned.

  - The Utah RLE reader did not validate that header information was
    reasonable given the file size.

  - A heap overflow error in the 'EscapeParenthesis' function.

  - A buffer overflow error in the MVG and SVG rendering code.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a heap read overflow which could allow an untrusted file to
  crash the software, cause huge memory allocations and/or consume huge amounts
  of CPU, cause a denial of service and to have some unspecified impacts.");

  script_tag(name:"affected", value:"GraphicsMagick version before 1.3.25
  on Windows");

  script_tag(name:"solution", value:"Upgrade to GraphicsMagick version 1.3.25
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://blogs.gentoo.org/ago/2016/08/23/graphicsmagick-two-heap-based-buffer-overflow-in-readtiffimage-tiff-c");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93074");
  script_xref(name:"URL", value:"https://blogs.gentoo.org/ago/2016/09/07/graphicsmagick-null-pointer-dereference-in-magickstrlcpy-utility-c");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/09/18/8");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q3/550");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_graphicsmagick_detect_win.nasl");
  script_mandatory_keys("GraphicsMagick/Win/Installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!gmVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:gmVer, test_version:"1.3.25"))
{
  report = report_fixed_ver(installed_version:gmVer, fixed_version:"1.3.25");
  security_message(data:report);
  exit(0);
}
