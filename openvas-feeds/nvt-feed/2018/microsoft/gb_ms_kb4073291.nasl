# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812740");
  script_version("2023-11-03T16:10:08+0000");
  script_cve_id("CVE-2017-5753", "CVE-2017-5715", "CVE-2017-5754");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-05 11:31:00 +0000 (Tue, 05 May 2020)");
  script_tag(name:"creation_date", value:"2018-01-22 12:24:05 +0530 (Mon, 22 Jan 2018)");
  script_name("Microsoft Windows Speculative Execution Side-Channel Vulnerabilities (KB4073291)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4073291.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple errors leading to 'speculative execution
  side-channel attacks' that affect many modern processors and operating systems
  including Intel, AMD, and ARM.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to read the content of memory across a trusted boundary and can therefore lead
  to information disclosure.");

  script_tag(name:"affected", value:"Microsoft Windows 10 Version 1709 for 32-bit Systems.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4073291");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102371");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102378");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102376");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
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

if(hotfix_check_sp(win10:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

exeVer = fetch_file_version(sysPath:sysPath, file_name:"Ntoskrnl.exe");
if(!exeVer){
  exit(0);
}

if(version_in_range(version:exeVer, test_version:"10.0.16299.0", test_version2:"10.0.16299.200"))
{
  report = 'File checked:     ' + sysPath + "\Ntoskrnl.exe" + '\n' +
           'File version:     ' + exeVer  + '\n' +
           'Vulnerable range: 10.0.16299.0 - 10.0.16299.200\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
