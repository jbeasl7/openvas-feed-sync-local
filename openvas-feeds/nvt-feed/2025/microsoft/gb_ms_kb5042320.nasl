# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836536");
  script_version("2025-08-01T05:45:36+0000");
  script_cve_id("CVE-2024-38163");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-01 05:45:36 +0000 (Fri, 01 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-14 00:15:07 +0000 (Wed, 14 Aug 2024)");
  script_tag(name:"creation_date", value:"2025-07-23 20:50:17 +0530 (Wed, 23 Jul 2025)");
  script_name("Microsoft Windows Elevation of Privilege Vulnerability (KB5042320)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5042320");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to elevate privileges.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 21H2 for 32-bit Systems

  - Microsoft Windows 10 Version 21H2 for x64-based Systems

  - Microsoft Windows 10 Version 22H2 for x64-based Systems

  - Microsoft Windows 10 Version 22H2 for 32-bit Systems

  - Microsoft Windows 11 version 21H2 for x64-based Systems

  - Microsoft Windows Server 2022");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5042320");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1, win2022:1, win11:1) <= 0) {
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
if(!registry_key_exists(key:key)) {
  exit(0);
}

build = registry_get_sz(key:key, item:"CurrentBuild");
if(!build) {
  exit(0);
}

winre = registry_get_sz(key:key, item:"WinREVersion");
if(!winre) {
  exit(0);
}

if(!("19044" >< build || "19045" >< build || "20348" >< build || "22000" >< build)) {
  exit(0);
}

if(("19044" >< build || "19045" >< build) && version_is_less(version:winre, test_version:"10.0.19041.3920")) {
  fix = "10.0.19041.3920";
}

if("20348" >< build && version_is_less(version:winre, test_version:"10.0.20348.2201")) {
  fix = "10.0.20348.2201";
}

if("22000" >< build && version_is_less(version:winre, test_version:"10.0.22000.2710")) {
  fix = "10.0.22000.2710";
}

if(fix) {
  report = report_fixed_ver(file_version:winre, vulnerable_range:"Less than " + fix);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
