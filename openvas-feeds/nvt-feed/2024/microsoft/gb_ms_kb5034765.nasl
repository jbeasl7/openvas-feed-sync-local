# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832818");
  script_version("2024-02-23T14:36:45+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2024-21420", "CVE-2024-21412", "CVE-2024-21406", "CVE-2024-21377",
                "CVE-2024-21375", "CVE-2024-21371", "CVE-2024-21370", "CVE-2024-21368",
                "CVE-2024-21366", "CVE-2024-21365", "CVE-2024-21362", "CVE-2024-21361",
                "CVE-2024-21360", "CVE-2024-21359", "CVE-2024-21358", "CVE-2024-21357",
                "CVE-2024-21356", "CVE-2024-21355", "CVE-2024-21354", "CVE-2024-21352",
                "CVE-2024-21351", "CVE-2024-21350", "CVE-2024-21349", "CVE-2024-21348",
                "CVE-2024-21347", "CVE-2024-21340", "CVE-2024-21339", "CVE-2024-20684",
                "CVE-2024-21304", "CVE-2024-21405", "CVE-2024-21391", "CVE-2024-21372",
                "CVE-2024-21369", "CVE-2024-21367", "CVE-2024-21363", "CVE-2024-21346",
                "CVE-2024-21344", "CVE-2024-21343", "CVE-2024-21342", "CVE-2024-21341",
                "CVE-2024-21338");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-23 14:36:45 +0000 (Fri, 23 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 18:16:00 +0000 (Tue, 13 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-14 10:03:05 +0530 (Wed, 14 Feb 2024)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5034765)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5034765");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Microsoft WDAC OLE DB provider for SQL Server Remote Code Execution Vulnerability.

  - Internet Shortcut Files Security Feature Bypass Vulnerability.

  - Windows DNS Information Disclosure Vulnerability.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to elevate privileges, execute arbitrary commands, bypass security
  feature, disclose information, conduct spoofing and denial of service attacks
  on an affected system.");

  script_tag(name:"affected", value:"- Microsoft Windows 11 version 22H2 for x64-based Systems

  - Microsoft Windows 11 Version 23H2 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5034765");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
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

if(hotfix_check_sp(win11:1) <= 0) {
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
if(!registry_key_exists(key:key)) {
  exit(0);
}

build = registry_get_sz(key:key, item:"CurrentBuild");
if(!build || (build != "22621" && build != "22631")) {
  exit(0);
}

dllPath = smb_get_systemroot();
if(!dllPath ) {
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"\system32\ntoskrnl.exe");
if(!fileVer) {
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"10.0.22621.0", test_version2:"10.0.22621.3154")) {
  report = report_fixed_ver(file_checked:dllPath + "\system32\ntoskrnl.exe", file_version:fileVer,
                            vulnerable_range:"10.0.22621.0 - 10.0.22621.3154");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
