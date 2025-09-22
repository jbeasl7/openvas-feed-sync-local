# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836065");
  script_version("2025-04-11T15:45:04+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2024-43629", "CVE-2024-43624", "CVE-2024-43451", "CVE-2024-43450",
                "CVE-2024-43637", "CVE-2024-43628", "CVE-2024-49039", "CVE-2024-49019",
                "CVE-2024-38203", "CVE-2024-43642", "CVE-2024-43641", "CVE-2024-43639",
                "CVE-2024-43636", "CVE-2024-43635", "CVE-2024-43633", "CVE-2024-43622",
                "CVE-2024-43621", "CVE-2024-43620", "CVE-2024-49046", "CVE-2024-38264",
                "CVE-2024-43452", "CVE-2024-43449", "CVE-2024-43646", "CVE-2024-43644",
                "CVE-2024-43643", "CVE-2024-43638", "CVE-2024-43634", "CVE-2024-43631",
                "CVE-2024-43630", "CVE-2024-43627", "CVE-2024-43626", "CVE-2024-43625",
                "CVE-2024-43623");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-12 18:15:33 +0000 (Tue, 12 Nov 2024)");
  script_tag(name:"creation_date", value:"2025-03-25 14:49:00 +0530 (Tue, 25 Mar 2025)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5046617)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5046617");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to elevate privileges, execute arbitrary commands, disclose information,
  conduct spoofing and denial of service attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows Server 2025

  - Microsoft Windows 11 version 24H2 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5046617");
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

dllPath = smb_get_system32root();
if(!dllPath ) {
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"ntoskrnl.exe");
if(!fileVer) {
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"10.0.26100.0", test_version2:"10.0.26100.2313")) {
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe", file_version:fileVer, vulnerable_range:"10.0.26100.0 - 10.0.26100.2313");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
