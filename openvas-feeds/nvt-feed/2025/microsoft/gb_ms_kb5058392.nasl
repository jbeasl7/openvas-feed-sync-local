# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836302");
  script_version("2025-08-29T05:38:41+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2025-30397", "CVE-2025-29969", "CVE-2025-24063", "CVE-2025-32707",
                "CVE-2025-30388", "CVE-2025-30385", "CVE-2025-29974", "CVE-2025-29963",
                "CVE-2025-29962", "CVE-2025-29961", "CVE-2025-29958", "CVE-2025-29957",
                "CVE-2025-29956", "CVE-2025-29954", "CVE-2025-29842", "CVE-2025-29840",
                "CVE-2025-29839", "CVE-2025-29837", "CVE-2025-29836", "CVE-2025-29835",
                "CVE-2025-29833", "CVE-2025-29832", "CVE-2025-29831", "CVE-2025-29830",
                "CVE-2025-29829", "CVE-2025-26677", "CVE-2025-32709", "CVE-2025-32706",
                "CVE-2025-32701", "CVE-2025-30400", "CVE-2025-30394", "CVE-2025-27468",
                "CVE-2025-29968", "CVE-2025-29967", "CVE-2025-29966", "CVE-2025-29964",
                "CVE-2025-29960", "CVE-2025-29959", "CVE-2025-47955", "CVE-2025-55229");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-29 05:38:41 +0000 (Fri, 29 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-13 17:15:57 +0000 (Tue, 13 May 2025)");
  script_tag(name:"creation_date", value:"2025-05-14 10:13:00 +0530 (Wed, 14 May 2025)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5058392)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5058392");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to elevate privileges, execute arbitrary commands, disclose information and
  conduct denial of service attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1809 for 32-bit Systems

  - Microsoft Windows 10 Version 1809 for x64-based Systems

  - Microsoft Windows Server 2019");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5058392");
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

if(hotfix_check_sp(win10:1, win10x64:1, win2019:1) <= 0) {
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

if(version_in_range(version:fileVer, test_version:"10.0.17763.0", test_version2:"10.0.17763.7308")) {
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"10.0.17763.0 - 10.0.17763.7308");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
