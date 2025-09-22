# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:ie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834411");
  script_version("2024-08-23T05:05:37+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2024-38178");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-08-23 05:05:37 +0000 (Fri, 23 Aug 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-13 18:15:26 +0000 (Tue, 13 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-14 16:23:31 +0530 (Wed, 14 Aug 2024)");
  script_name("Microsoft Internet Explorer Memory Corruption Vulnerability (KB5041770)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5041770");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a memory corruption
  vulnerability in Scripting Engine.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct code execution.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 11.x.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5041770");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/IE/Version");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2008r2:2, win2012:1, win2012R2:1) <= 0) {
  exit(0);
}

ieVer = get_app_version(cpe:CPE);
if(!ieVer || ieVer !~ "^11\.") {
  exit(0);
}

iePath = smb_get_system32root();
if(!iePath ) {
  exit(0);
}

iedllVer = fetch_file_version(sysPath:iePath, file_name:"Mshtml.dll");
if(!iedllVer) {
  exit(0);
}

if(version_is_less(version:iedllVer, test_version:"11.0.9600.22122")) {
  report = report_fixed_ver(file_checked:iePath + "\Mshtml.dll", file_version:iedllVer, vulnerable_range:"Less than 11.0.9600.22122");
  security_message(data:report);
  exit(0);
}

exit(99);
