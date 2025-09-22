# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810847");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-0184");
  script_tag(name:"cvss_base", value:"5.2");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-18 16:36:00 +0000 (Tue, 18 Apr 2017)");
  script_tag(name:"creation_date", value:"2017-04-12 11:24:16 +0530 (Wed, 12 Apr 2017)");
  script_name("Microsoft Windows Hyper-V Denial of Service Vulnerability (KB3217841)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3217841.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when Microsoft Hyper-V on a
  host server fails to properly validate input from a privileged user on a guest
  operating system.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  who already has a privileged account on a guest operating system, running as a
  virtual machine, could run a specially crafted application that causes a host
  machine to crash.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2008 x64 Edition Service Pack 2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3217841");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97435");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3217841/security-update-for-the-hyper-v-denial-of-service-vulnerability");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2008x64:3) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

qzVer = fetch_file_version(sysPath:sysPath, file_name:"Isoparser.sys");
if(!qzVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3, winVistax64:3, win2008:3, win2008x64:3) > 0)
{
  if(version_is_less(version:qzVer, test_version:"6.0.6002.19728"))
  {
    Vulnerable_range = "Less than 6.0.6002.19728";
    VULN = TRUE ;
  }

  else if(version_in_range(version:qzVer, test_version:"6.6.6002.24000", test_version2:"6.0.6002.24050"))
  {
    Vulnerable_range = "6.6.6002.24000 - 6.0.6002.24050";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\Isoparser.sys" + '\n' +
           'File version:     ' + qzVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
