# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836407");
  script_version("2025-08-07T05:44:51+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2025-33057", "CVE-2025-33053", "CVE-2025-32724", "CVE-2025-32720",
                "CVE-2025-32713", "CVE-2025-3052", "CVE-2025-33073", "CVE-2025-33070",
                "CVE-2025-33069", "CVE-2025-33068", "CVE-2025-33056", "CVE-2025-33055",
                "CVE-2025-33052", "CVE-2025-33050", "CVE-2025-32725", "CVE-2025-24065",
                "CVE-2025-24069", "CVE-2025-24068", "CVE-2025-33071", "CVE-2025-47160",
                "CVE-2025-33075", "CVE-2025-33067", "CVE-2025-33066", "CVE-2025-33065",
                "CVE-2025-33064", "CVE-2025-33063", "CVE-2025-33062", "CVE-2025-33061",
                "CVE-2025-33060", "CVE-2025-33059", "CVE-2025-33058", "CVE-2025-32722",
                "CVE-2025-32721", "CVE-2025-32719", "CVE-2025-32718", "CVE-2025-32715",
                "CVE-2025-32714", "CVE-2025-32712", "CVE-2025-29828", "CVE-2025-49735");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-07 05:44:51 +0000 (Thu, 07 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-10 17:23:02 +0000 (Tue, 10 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-06-11 10:24:01 +0530 (Wed, 11 Jun 2025)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5060842)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5060842");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to elevate privileges, execute arbitrary commands, disclose information,
  bypass security restrictions and conduct denial of service attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows Server 2025

  - Microsoft Windows 11 version 24H2 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5060842");
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

if(hotfix_check_sp(win2025:1, win11:1) <= 0) {
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
if(!registry_key_exists(key:key)) {
  exit(0);
}

build = registry_get_sz(key:key, item:"CurrentBuild");
if(!build || build != "26100") {
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

if(version_in_range(version:fileVer, test_version:"10.0.26100.0", test_version2:"10.0.26100.4342")) {
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe", file_version:fileVer, vulnerable_range:"10.0.26100.0 - 10.0.26100.4342");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);