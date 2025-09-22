# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805010");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-4076");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-11-12 08:19:24 +0530 (Wed, 12 Nov 2014)");
  script_name("Microsoft Windows TCP/IP Privilege Elevation Vulnerability (2989935)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS14-070.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error in
  the tcpip.sys and tcpip6.sys drivers when processing certain IOCTL.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to  execute arbitrary code.");

  script_tag(name:"affected", value:"Microsoft Windows 2003 x32/x64 Service Pack 2 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2989935");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70976");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS14-070");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
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

if(hotfix_check_sp(win2003:3, win2003x64:3) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

win32SysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\drivers\tcpip.sys");
if(!win32SysVer){
  exit(0);
}

if(hotfix_check_sp(win2003x64:3,win2003:3) > 0)
{
  if(version_is_less(version:win32SysVer, test_version:"5.2.3790.5440")){
    report = report_fixed_ver(installed_version:win32SysVer, fixed_version:"5.2.3790.5440", install_path:sysPath);
    security_message(port:0, data:report);
  }
  exit(0);
}
