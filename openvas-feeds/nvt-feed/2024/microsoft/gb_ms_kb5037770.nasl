# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832994");
  script_version("2024-08-09T05:05:42+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2024-30040", "CVE-2024-30051", "CVE-2024-30049", "CVE-2024-30038",
                "CVE-2024-30039", "CVE-2024-30037", "CVE-2024-30035", "CVE-2024-30034",
                "CVE-2024-30033", "CVE-2024-30032", "CVE-2024-30031", "CVE-2024-30029",
                "CVE-2024-30028", "CVE-2024-30027", "CVE-2024-30025", "CVE-2024-30024",
                "CVE-2024-29994", "CVE-2024-30050", "CVE-2024-30023", "CVE-2024-30022",
                "CVE-2024-30021", "CVE-2024-30020", "CVE-2024-30018", "CVE-2024-30017",
                "CVE-2024-30016", "CVE-2024-30015", "CVE-2024-30014", "CVE-2024-30012",
                "CVE-2024-30009", "CVE-2024-30008", "CVE-2024-30006", "CVE-2024-30005",
                "CVE-2024-30004", "CVE-2024-30003", "CVE-2024-30002", "CVE-2024-30001",
                "CVE-2024-30000", "CVE-2024-29999", "CVE-2024-29998", "CVE-2024-29997",
                "CVE-2024-29996");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-08-09 05:05:42 +0000 (Fri, 09 Aug 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-14 17:17:12 +0000 (Tue, 14 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-15 14:41:21 +0530 (Wed, 15 May 2024)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5037770)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5037770");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-30040: Windows MSHTML Platform Security Feature Bypass Vulnerability

  - CVE-2024-30051: Windows DWM Core Library Elevation of Privilege Vulnerability

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to elevate privileges, execute arbitrary commands, disclose information and
  bypass security restrictions.");

  script_tag(name:"affected", value:"Microsoft Windows 11 version 21H2 for x64-based Systems.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5037770");
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

dllPath = smb_get_systemroot();
if(!dllPath ) {
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"\system32\ntoskrnl.exe");
if(!fileVer) {
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"10.0.22000.2960")) {
  report = report_fixed_ver(file_checked:dllPath + "\system32\ntoskrnl.exe", file_version:fileVer, vulnerable_range:"Less than 10.0.22000.2960");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
