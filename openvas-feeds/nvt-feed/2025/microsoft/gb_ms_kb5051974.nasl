# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834943");
  script_version("2025-04-11T15:45:04+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2025-21373", "CVE-2025-21212", "CVE-2025-21376", "CVE-2025-21414",
                "CVE-2025-21254", "CVE-2025-21216", "CVE-2025-21184", "CVE-2025-21181",
                "CVE-2025-21377", "CVE-2025-21371", "CVE-2025-21367", "CVE-2025-21359",
                "CVE-2025-21358", "CVE-2025-21350", "CVE-2025-21349", "CVE-2025-21347",
                "CVE-2025-21337", "CVE-2025-21201", "CVE-2025-21200", "CVE-2025-21190",
                "CVE-2025-21407", "CVE-2025-21406", "CVE-2025-21420", "CVE-2025-21419",
                "CVE-2025-21418", "CVE-2025-21391", "CVE-2025-21375", "CVE-2025-21369",
                "CVE-2025-21368", "CVE-2025-21352", "CVE-2025-21351");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-11 18:15:39 +0000 (Tue, 11 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-02-12 09:46:48 +0530 (Wed, 12 Feb 2025)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5051974)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5051974");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to elevate privileges, execute arbitrary commands, disclose information,
  bypass security restrictions, spoofing and conduct denial of service
  attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 21H2 for 32-bit Systems

  - Microsoft Windows 10 Version 21H2 for x64-based Systems

  - Microsoft Windows 10 Version 22H2 for x64-based Systems

  - Microsoft Windows 10 Version 22H2 for 32-bit Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5051974");
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

if(hotfix_check_sp(win10:1, win10x64:1) <= 0) {
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

if(!("19044" >< build || "19045" >< build)) {
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath ) {
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"ntoskrnl.exe");
if(!fileVer) {
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"10.0.19041.5486")) {
  report = report_fixed_ver(file_checked:dllPath + "\ntoskrnl.exe", file_version:fileVer, vulnerable_range:"Less than 10.0.19041.5486");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);