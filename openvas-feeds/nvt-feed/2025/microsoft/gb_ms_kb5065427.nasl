# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836635");
  script_version("2025-09-15T05:39:20+0000");
  script_cve_id("CVE-2025-54114", "CVE-2025-54098", "CVE-2025-53803", "CVE-2025-54096",
                "CVE-2025-55234", "CVE-2025-54917", "CVE-2025-54915", "CVE-2025-54912",
                "CVE-2025-54911", "CVE-2025-54116", "CVE-2025-54113", "CVE-2025-54112",
                "CVE-2025-54109", "CVE-2025-54107", "CVE-2025-54104", "CVE-2025-54094",
                "CVE-2025-54093", "CVE-2025-54091", "CVE-2025-53810", "CVE-2025-53808",
                "CVE-2025-53806", "CVE-2025-53804", "CVE-2025-53801", "CVE-2025-53800",
                "CVE-2025-53799", "CVE-2025-53796", "CVE-2025-55226", "CVE-2025-55225",
                "CVE-2025-54918", "CVE-2025-54916", "CVE-2025-54913", "CVE-2025-54895",
                "CVE-2025-54894", "CVE-2025-54111", "CVE-2025-54110", "CVE-2025-54106",
                "CVE-2025-54102", "CVE-2025-54101", "CVE-2025-54099", "CVE-2025-54097",
                "CVE-2025-54095", "CVE-2025-53798", "CVE-2025-53797", "CVE-2025-49734");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-15 05:39:20 +0000 (Mon, 15 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-12 14:44:14 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-10 09:39:52 +0530 (Wed, 10 Sep 2025)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5065427)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5065427");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to elevate privileges, execute arbitrary commands, disclose information,
  bypass security restrictions and conduct denial of service attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1607 for 32-bit Systems

  - Microsoft Windows 10 Version 1607 for x64-based Systems

  - Microsoft Windows Server 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5065427");
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

if(version_in_range(version:fileVer, test_version:"10.0.14393.0", test_version2:"10.0.14393.8421")) {
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"10.0.14393.0 - 10.0.14393.8421");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);