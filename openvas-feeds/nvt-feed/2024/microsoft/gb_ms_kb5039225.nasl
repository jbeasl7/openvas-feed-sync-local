# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834042");
  script_version("2024-09-06T15:39:29+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2024-30099", "CVE-2024-30097", "CVE-2024-30095", "CVE-2024-30094",
                "CVE-2024-30093", "CVE-2024-30091", "CVE-2024-30090", "CVE-2024-30088",
                "CVE-2024-30087", "CVE-2024-30086", "CVE-2024-30084", "CVE-2024-30068",
                "CVE-2024-30067", "CVE-2024-30066", "CVE-2024-30065", "CVE-2024-30063",
                "CVE-2024-35250", "CVE-2024-30082", "CVE-2024-30080", "CVE-2024-30078",
                "CVE-2024-30077", "CVE-2024-30069", "CVE-2024-38213");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-06 15:39:29 +0000 (Fri, 06 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-11 17:15:55 +0000 (Tue, 11 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-06-12 10:27:30 +0530 (Wed, 12 Jun 2024)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5039225)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5039225");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-30099: Windows Kernel Elevation of Privilege Vulnerability

  - CVE-2024-30097: Microsoft Speech Application Programming Interface (SAPI) Remote Code Execution Vulnerability

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to elevate privileges, execute arbitrary commands, disclose information and
  conduct denial of service attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 for 32-bit Systems

  - Microsoft Windows 10 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5039225");
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

if(hotfix_check_sp(win10:1, win10x64:1) <= 0) {
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

if(version_in_range(version:fileVer, test_version:"10.0.10240.0", test_version2:"10.0.10240.20679")) {
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe", file_version:fileVer, vulnerable_range:"10.0.10240.0 - 10.0.10240.20679");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
