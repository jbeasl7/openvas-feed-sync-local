# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834648");
  script_version("2024-11-29T15:40:53+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2024-43562", "CVE-2024-43553", "CVE-2024-43511", "CVE-2024-43607",
                "CVE-2024-43534", "CVE-2024-43484", "CVE-2024-43483", "CVE-2024-43611",
                "CVE-2024-43583", "CVE-2024-43599", "CVE-2024-43593", "CVE-2024-43592",
                "CVE-2024-43589", "CVE-2024-43575", "CVE-2024-43572", "CVE-2024-43570",
                "CVE-2024-43567", "CVE-2024-43565", "CVE-2024-43564", "CVE-2024-43563",
                "CVE-2024-43560", "CVE-2024-43556", "CVE-2024-43551", "CVE-2024-43550",
                "CVE-2024-43549", "CVE-2024-43547", "CVE-2024-43545", "CVE-2024-43544",
                "CVE-2024-43521", "CVE-2024-43520", "CVE-2024-43517", "CVE-2024-43514",
                "CVE-2024-43512", "CVE-2024-43509", "CVE-2024-43501", "CVE-2024-43456",
                "CVE-2024-30092", "CVE-2024-38212", "CVE-2024-43453", "CVE-2024-38262",
                "CVE-2024-38265", "CVE-2024-38124", "CVE-2024-38149", "CVE-2024-37983",
                "CVE-2024-37979", "CVE-2024-37982", "CVE-2024-37976", "CVE-2024-43608",
                "CVE-2024-43573", "CVE-2024-43554", "CVE-2024-43541", "CVE-2024-43535",
                "CVE-2024-43532", "CVE-2024-43519", "CVE-2024-43518", "CVE-2024-43515",
                "CVE-2024-43513", "CVE-2024-43506", "CVE-2024-38261", "CVE-2024-43516",
                "CVE-2024-38202");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-11-29 15:40:53 +0000 (Fri, 29 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-08 18:15:07 +0000 (Tue, 08 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-10-09 11:01:47 +0530 (Wed, 09 Oct 2024)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5044293)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5044293");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-43562: Windows Network Address Translation (NAT) Denial of Service Vulnerability

  - CVE-2024-43553: NT OS Kernel Elevation of Privilege Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to elevate privileges, execute arbitrary commands, disclose information,
  bypass security restrictions, conduct spoofing and denial of service
  attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1607 for 32-bit Systems

  - Microsoft Windows 10 Version 1607 for x64-based Systems

  - Microsoft Windows Server 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5044293");
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

if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) <= 0) {
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

if(version_in_range(version:fileVer, test_version:"10.0.14393.0", test_version2:"10.0.14393.7425")) {
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"10.0.14393.0 - 10.0.14393.7425");
  security_message(port:0, data:report);
  exit(0);
}
