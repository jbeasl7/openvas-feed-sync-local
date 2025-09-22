# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810793");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-8483");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-18 20:48:00 +0000 (Mon, 18 Mar 2019)");
  script_tag(name:"creation_date", value:"2017-06-14 12:53:59 +0530 (Wed, 14 Jun 2017)");
  script_name("Microsoft Windows Kernel Information Disclosure Vulnerability (KB4022883)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4022883");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when the Windows kernel
  improperly initializes objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to
  obtain information to further compromise the users system.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4022883");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98859");
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

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

asVer = fetch_file_version(sysPath:sysPath, file_name:"Atmfd.dll");
if(!asVer){
  exit(0);
}

if(version_is_less(version:asVer, test_version:"5.1.2.252"))
{
  report = 'File checked:     ' + sysPath + "\Atmfd.dll" + '\n' +
           'File version:     ' + asVer  + '\n' +
           'Vulnerable range: Less than 5.1.2.252\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
