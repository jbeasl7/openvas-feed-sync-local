# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811031");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-0242");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-28 12:58:00 +0000 (Mon, 28 Sep 2020)");
  script_tag(name:"creation_date", value:"2017-05-10 11:36:48 +0530 (Wed, 10 May 2017)");
  script_name("Microsoft ActiveX 'Msadcf.dll' Information Disclosure Vulnerability (KB4018927)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4018927.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to some error in the
  way some ActiveX objects are instantiated.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain access to sensitive information which can aid in further compromise of
  the user's system.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4018927");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98275");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0242");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

if(hotfix_check_sp(win2008:3, win2008x64:3) <= 0){
  exit(0);
}

path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
if(!path){
  exit(0);
}

filePath = path + "\System\msadc";
fileVer = fetch_file_version(sysPath:filePath, file_name:"msadcf.dll");

if(version_is_less(version:fileVer, test_version:"6.0.6002.19770"))
{
  VULN = TRUE ;
  vulnerable_range = "Less than 6.0.6002.19770";
}
else if(version_in_range(version:fileVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.24088"))
{
  VULN = TRUE ;
  vulnerable_range = "6.0.6002.23000 - 6.0.6002.24088";
}

if(VULN)
{
  report = 'File checked:     ' + filePath + "\msadcf.dll" + '\n' +
           'File version:     ' + fileVer  + '\n' +
           'Vulnerable range: ' + vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
