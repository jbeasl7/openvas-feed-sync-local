# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:seamonkey";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804045");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2013-5609", "CVE-2013-5610", "CVE-2013-5612", "CVE-2013-5613",
                "CVE-2013-5614", "CVE-2013-5615", "CVE-2013-5616", "CVE-2013-5618",
                "CVE-2013-5619", "CVE-2013-6671", "CVE-2013-6672", "CVE-2013-6673");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-12 14:42:00 +0000 (Wed, 12 Aug 2020)");
  script_tag(name:"creation_date", value:"2013-12-23 18:34:28 +0530 (Mon, 23 Dec 2013)");
  script_name("SeaMonkey Multiple Vulnerabilities-01 (Dec 2013) - Windows");


  script_tag(name:"summary", value:"SeaMonkey is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to SeaMonkey version 2.23 or later.");
  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");
  script_tag(name:"affected", value:"SeaMonkey version before 2.23 on Windows");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct cross-site scripting
attacks, bypass certain security restrictions, disclose potentially sensitive
information, and compromise a user's system.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56002");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64203");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64204");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64205");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64206");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64207");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64209");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64210");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64211");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64212");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64213");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64215");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64216");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-104.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_seamonkey_detect_win.nasl");
  script_mandatory_keys("Seamonkey/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!smVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:smVer, test_version:"2.23"))
{
  report = report_fixed_ver(installed_version:smVer, fixed_version:"2.23");
  security_message(port: 0, data: report);
  exit(0);
}
