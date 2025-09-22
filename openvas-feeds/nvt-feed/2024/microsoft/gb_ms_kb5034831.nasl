# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832825");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2024-21420", "CVE-2024-21406", "CVE-2024-21375", "CVE-2024-21370",
                "CVE-2024-21368", "CVE-2024-21366", "CVE-2024-21365", "CVE-2024-21361",
                "CVE-2024-21360", "CVE-2024-21359", "CVE-2024-21358", "CVE-2024-21357",
                "CVE-2024-21356", "CVE-2024-21355", "CVE-2024-21354", "CVE-2024-21352",
                "CVE-2024-21350", "CVE-2024-21349", "CVE-2024-21347", "CVE-2024-21340",
                "CVE-2023-50387", "CVE-2024-21405", "CVE-2024-21391", "CVE-2024-21372",
                "CVE-2024-21369", "CVE-2024-21367", "CVE-2024-21363");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 18:16:00 +0000 (Tue, 13 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-14 14:20:11 +0530 (Wed, 14 Feb 2024)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5034831)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5034831");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Microsoft WDAC OLE DB provider for SQL Server Remote Code Execution Vulnerability.

  - Windows Printing Service Spoofing Vulnerability.

  - Microsoft WDAC OLE DB provider for SQL Server Remote Code Execution Vulnerability.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to elevate privileges, execute arbitrary commands, disclose
  information, conduct spoofing and denial of service attacks on an affected
  system.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5034831");
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

if(hotfix_check_sp(win2008r2:2) <= 0) {
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath ) {
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"Conhost.exe");
if(!fileVer) {
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.1.7601.26958")) {
  report = report_fixed_ver(file_checked:dllPath + "\Conhost.exe",
                            file_version:fileVer, vulnerable_range:"Less than 6.1.7601.26958");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
