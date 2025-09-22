# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836485");
  script_version("2025-08-29T05:38:41+0000");
  script_cve_id("CVE-2025-49659", "CVE-2025-49732", "CVE-2025-49725", "CVE-2025-49685",
                "CVE-2025-49684", "CVE-2025-48818", "CVE-2025-48816", "CVE-2025-49683",
                "CVE-2025-49682", "CVE-2025-49722", "CVE-2025-49675", "CVE-2025-49660",
                "CVE-2025-49742", "CVE-2025-49679", "CVE-2025-48822", "CVE-2025-48819",
                "CVE-2025-49733", "CVE-2025-49693", "CVE-2025-49667", "CVE-2025-49727",
                "CVE-2025-49678", "CVE-2025-49665", "CVE-2025-48821", "CVE-2025-47972",
                "CVE-2025-49740", "CVE-2025-49730", "CVE-2025-49724", "CVE-2025-49664",
                "CVE-2025-48820", "CVE-2025-48811", "CVE-2025-48802", "CVE-2025-47982",
                "CVE-2025-47975", "CVE-2025-49689", "CVE-2025-49677", "CVE-2025-47985",
                "CVE-2025-49744", "CVE-2025-47999", "CVE-2025-49680", "CVE-2025-48823",
                "CVE-2025-48817", "CVE-2025-48815", "CVE-2025-48814", "CVE-2025-48808",
                "CVE-2025-48806", "CVE-2025-48805", "CVE-2025-48804", "CVE-2025-48803",
                "CVE-2025-48800", "CVE-2025-48799", "CVE-2025-48003", "CVE-2025-48001",
                "CVE-2025-48000", "CVE-2025-47996", "CVE-2025-47981", "CVE-2025-47980",
                "CVE-2025-47973", "CVE-2025-49760", "CVE-2025-49726", "CVE-2025-49723",
                "CVE-2025-49721", "CVE-2025-36350", "CVE-2025-36357", "CVE-2025-47991",
                "CVE-2025-49691", "CVE-2025-49690", "CVE-2025-49687", "CVE-2025-49686",
                "CVE-2025-49661", "CVE-2025-49658", "CVE-2025-47987", "CVE-2025-47986",
                "CVE-2025-47984", "CVE-2025-47976", "CVE-2025-47971", "CVE-2025-47159",
                "CVE-2025-33054", "CVE-2025-53789", "CVE-2025-48807", "CVE-2025-55230");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-29 05:38:41 +0000 (Fri, 29 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-08 17:15:38 +0000 (Tue, 08 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-09 09:12:56 +0530 (Wed, 09 Jul 2025)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5062552)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5062552");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to elevate privileges, execute arbitrary commands, disclose information,
  bypass security restrictions, conduct spoofing and denial of service attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 11 version 22H2 for x64-based Systems

  - Microsoft Windows 11 Version 23H2 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5062552");
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

if(version_in_range(version:fileVer, test_version:"10.0.22621.0", test_version2:"10.0.22621.5623")) {
  report = report_fixed_ver(file_checked:dllPath + "\system32\ntoskrnl.exe", file_version:fileVer,
                            vulnerable_range:"10.0.22621.0 - 10.0.22621.5623");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);