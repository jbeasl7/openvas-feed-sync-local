# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834803");
  script_version("2025-01-31T15:39:24+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2024-49105", "CVE-2024-49116", "CVE-2024-49112", "CVE-2024-49081",
                "CVE-2024-49125", "CVE-2024-49108", "CVE-2024-49091", "CVE-2024-49138",
                "CVE-2024-49128", "CVE-2024-49127", "CVE-2024-49118", "CVE-2024-49114",
                "CVE-2024-49113", "CVE-2024-49110", "CVE-2024-49109", "CVE-2024-49095",
                "CVE-2024-49090", "CVE-2024-49088", "CVE-2024-49083", "CVE-2024-49082",
                "CVE-2024-49080", "CVE-2024-49079", "CVE-2024-49078", "CVE-2024-49077",
                "CVE-2024-49076", "CVE-2024-49075", "CVE-2024-49072", "CVE-2024-49132",
                "CVE-2024-49129", "CVE-2024-49126", "CVE-2024-49124", "CVE-2024-49123",
                "CVE-2024-49122", "CVE-2024-49121", "CVE-2024-49120", "CVE-2024-49119",
                "CVE-2024-49115", "CVE-2024-49111", "CVE-2024-49107", "CVE-2024-49106",
                "CVE-2024-49104", "CVE-2024-49103", "CVE-2024-49102", "CVE-2024-49101",
                "CVE-2024-49099", "CVE-2024-49098", "CVE-2024-49097", "CVE-2024-49096",
                "CVE-2024-49094", "CVE-2024-49092", "CVE-2024-49089", "CVE-2024-49087",
                "CVE-2024-49086", "CVE-2024-49085", "CVE-2024-49084", "CVE-2024-49074",
                "CVE-2024-49073");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-31 15:39:24 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-12 02:04:37 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-12-11 09:55:55 +0530 (Wed, 11 Dec 2024)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5048661)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5048661");

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
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5048661");
  script_xref(name:"URL", value:"https://www.safebreach.com/blog/ldapnightmare-safebreach-labs-publishes-first-proof-of-concept-exploit-for-cve-2024-49113/");
  script_xref(name:"URL", value:"https://github.com/SafeBreach-Labs/CVE-2024-49113");
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

if(version_in_range(version:fileVer, test_version:"10.0.17763.0", test_version2:"10.0.17763.6639")) {
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"10.0.17763.0 - 10.0.17763.6639");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
