# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834405");
  script_version("2024-08-23T05:05:37+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2024-38146", "CVE-2024-38143", "CVE-2024-38140", "CVE-2024-38122",
                "CVE-2024-38106", "CVE-2024-38178", "CVE-2024-38223", "CVE-2022-3775",
                "CVE-2024-38180", "CVE-2024-38153", "CVE-2024-38152", "CVE-2024-38151",
                "CVE-2024-38145", "CVE-2024-38144", "CVE-2024-38142", "CVE-2024-38141",
                "CVE-2024-38134", "CVE-2024-38132", "CVE-2024-38131", "CVE-2024-38130",
                "CVE-2024-38127", "CVE-2024-38126", "CVE-2024-38125", "CVE-2024-38118",
                "CVE-2024-38117", "CVE-2024-38116", "CVE-2024-38115", "CVE-2024-38114",
                "CVE-2024-29995", "CVE-2024-38107", "CVE-2024-38063", "CVE-2023-40547",
                "CVE-2024-38199", "CVE-2024-38198", "CVE-2024-38196", "CVE-2024-38193",
                "CVE-2022-2601");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-08-23 05:05:37 +0000 (Fri, 23 Aug 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-13 18:15:29 +0000 (Tue, 13 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-14 11:25:37 +0530 (Wed, 14 Aug 2024)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5041782)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5041782");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-38152: Windows OLE Remote Code Execution Vulnerability

  - CVE-2024-38143: Windows WLAN AutoConfig Service Elevation of Privilege Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to elevate privileges, execute arbitrary commands, disclose information,
  bypass security restrictions and conduct denial of service attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 for 32-bit Systems

  - Microsoft Windows 10 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5041782");
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

if(version_in_range(version:fileVer, test_version:"10.0.10240.0", test_version2:"10.0.10240.20746")) {
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe", file_version:fileVer, vulnerable_range:"10.0.10240.0 - 10.0.10240.20746");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
