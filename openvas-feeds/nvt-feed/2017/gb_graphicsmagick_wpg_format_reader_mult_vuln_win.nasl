# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:graphicsmagick:graphicsmagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810537");
  script_version("2024-02-08T05:05:59+0000");
  script_cve_id("CVE-2016-7996", "CVE-2016-7997", "CVE-2016-7800");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");
  script_tag(name:"creation_date", value:"2017-02-02 14:58:13 +0530 (Thu, 02 Feb 2017)");
  script_name("GraphicsMagick Multiple Vulnerabilities (Feb 2017) - Windows");

  script_tag(name:"summary", value:"GraphicsMagick is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as,

  - In a build with QuantumDepth=8 (the default), there is no check that the
    provided colormap is not larger than 256 entries, resulting in potential
    heap overflow.

  - A logic error which leads to passing a NULL pointer where a NULL pointer
    is not allowed.

  - An integer underflow error in the parse8BIM function in coders/meta.c
    script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service and to have unspecified impact.");

  script_tag(name:"affected", value:"GraphicsMagick version 1.3.25 and earlier
  on Windows");

  script_tag(name:"solution", value:"Apply the appropriate patch from the vendor.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/10/08/5");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93467");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93464");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96135");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/10/01/7");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q4/55");

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

if(version_is_less_equal(version:gmVer, test_version:"1.3.25"))
{
  report = report_fixed_ver(installed_version:gmVer, fixed_version:"Apply the patch");
  security_message(data:report);
  exit(0);
}
