# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mcafee:application_control";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806980");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2016-1715");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:P/I:P/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-01-21 17:06:00 +0000 (Thu, 21 Jan 2016)");
  script_tag(name:"creation_date", value:"2016-01-20 15:17:03 +0530 (Wed, 20 Jan 2016)");
  script_name("McAfee Application Control Multiple Vulnerabilities (Jan 2016) - Windows");

  script_tag(name:"summary", value:"McAfee Application Control is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in
  swin.sys kernel driver.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local
  attacker to conduct denial of service and execute arbitrary code on the affected
  system.");

  script_tag(name:"affected", value:"McAfee Application Control 6.1.0 before
  build 706, 6.1.1 before build 404, 6.1.2 before build 449, 6.1.3 before build
  441 and 6.2.0 before build 505 on 32-bit Windows platforms.");

  script_tag(name:"solution", value:"Upgrade to McAfee Application Control
  versions 6.1.0 build 706 or later, or 6.1.1 build 404 or later, or 6.1.2 build
  449 or later, or 6.1.3 build 441 or later, or 6.2.0 build 505 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-007");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/80167");
  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10145");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mcafee_application_control_detect.nasl");
  script_mandatory_keys("McAfee/Application/Control/Win/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x64" >< os_arch){
  exit(0);
}

if(!mcafeeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:mcafeeVer, test_version:"6.1.0", test_version2:"6.1.0.705"))
{
  fix = "6.1.0 build 706";
  VULN = TRUE;
}

else if(version_in_range(version:mcafeeVer, test_version:"6.1.1", test_version2:"6.1.1.403"))
{
  fix = "6.1.1 build 404";
  VULN = TRUE;
}

else if(version_in_range(version:mcafeeVer, test_version:"6.1.2", test_version2:"6.1.2.448"))
{
  fix = "6.1.2 build 449";
  VULN = TRUE;
}

else if(version_in_range(version:mcafeeVer, test_version:"6.1.3", test_version2:"6.1.3.440"))
{
  fix = "6.1.3 build 441";
  VULN = TRUE;
}

else if(version_in_range(version:mcafeeVer, test_version:"6.2.0", test_version2:"6.2.0.504"))
{
  fix = "6.2.0 build 505";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:mcafeeVer, fixed_version: fix);
  security_message(data:report);
  exit(0);
}

exit(99);