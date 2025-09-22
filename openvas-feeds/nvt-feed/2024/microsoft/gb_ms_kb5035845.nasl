# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832866");
  script_version("2024-08-09T05:05:42+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-28746", "CVE-2024-26174", "CVE-2024-26170", "CVE-2024-21443",
                "CVE-2024-26161", "CVE-2024-21451", "CVE-2024-21442", "CVE-2024-21441",
                "CVE-2024-21439", "CVE-2024-21438", "CVE-2024-21437", "CVE-2024-21434",
                "CVE-2024-21433", "CVE-2024-21430", "CVE-2024-21429", "CVE-2024-26182",
                "CVE-2024-26181", "CVE-2024-26178", "CVE-2024-26177", "CVE-2024-26176",
                "CVE-2024-26173", "CVE-2024-26169", "CVE-2024-26166", "CVE-2024-26162",
                "CVE-2024-26159", "CVE-2024-21450", "CVE-2024-21446", "CVE-2024-21445",
                "CVE-2024-21444", "CVE-2024-21440", "CVE-2024-21436", "CVE-2024-21432",
                "CVE-2024-21431", "CVE-2024-21427", "CVE-2024-21408", "CVE-2024-21407");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-08-09 05:05:42 +0000 (Fri, 09 Aug 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-12 17:15:55 +0000 (Tue, 12 Mar 2024)");
  script_tag(name:"creation_date", value:"2024-03-13 14:53:54 +0530 (Wed, 13 Mar 2024)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5035845)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5035845");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-26174: Windows Kernel Information Disclosure Vulnerability

  - CVE-2024-21451: Microsoft ODBC Driver Remote Code Execution Vulnerability

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to elevate privileges, execute arbitrary commands, disclose
  information, bypass security restrictions and conduct denial of service
  attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 21H2 for 32-bit Systems

  - Microsoft Windows 10 Version 21H2 for x64-based Systems

  - Microsoft Windows 10 Version 22H2 for x64-based Systems

  - Microsoft Windows 10 Version 22H2 for 32-bit Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5035845");
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

if(version_is_less(version:fileVer, test_version:"10.0.19041.4170")) {
  report = report_fixed_ver(file_checked:dllPath + "\ntoskrnl.exe", file_version:fileVer, vulnerable_range:"Less than 10.0.19041.4170");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
