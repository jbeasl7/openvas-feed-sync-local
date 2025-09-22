# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902694");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2012-2531", "CVE-2012-2532");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-11-14 10:33:22 +0530 (Wed, 14 Nov 2012)");
  script_name("Microsoft Windows IIS FTP Service Information Disclosure Vulnerability (2761226)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2733829");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56440");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-073");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to gain access to sensitive
  information that may aid in further attacks.");

  script_tag(name:"affected", value:"- Microsoft FTP Service 7.0 for IIS 7.0 on Microsoft Windows Vista/2008 server Service Pack 2 and prior

  - Microsoft FTP Service 7.5 for IIS 7.5 on:

  - Microsoft Windows Vista/2008 server Service Pack 2 and prior

  - Microsoft Windows 7 Service Pack 1 and prior

  - Microsoft Windows Server 2008 R2 Service Pack 1 and prior");

  script_tag(name:"insight", value:"The flaws are due to

  - IIS improperly manages the permissions of a log file.

  - An error within the IIS FTP service when negotiating encrypted
    communications channels.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a moderate security update according to
  Microsoft Bulletin MS12-073.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3, win2008:3, win7:2, win2008r2:2) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\inetsrv\ftpsvc.dll");
if(dllVer)
{
  if(hotfix_check_sp(winVista:3, win2008:3) > 0)
  {
    ## File info is not given in bulletin taken based on patch
    if(version_in_range(version:dllVer, test_version:"7.5.7600.0", test_version2:"7.5.7600.14979"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  else if(hotfix_check_sp(win7:2, win2008r2:2) > 0)
  {
    dllVer2 = fetch_file_version(sysPath:sysPath, file_name:"system32\inetsrv\Aspnetca.exe");
    if(dllVer2)
    {
      if(version_is_less(version:dllVer, test_version:"7.5.7600.17034") ||
         version_in_range(version:dllVer, test_version:"7.5.7600.20000", test_version2:"7.5.7600.21223")||
         version_in_range(version:dllVer, test_version:"7.5.7601.17000", test_version2:"7.5.7601.17854")||
         version_in_range(version:dllVer, test_version:"7.5.7601.21000", test_version2:"7.5.7601.22008")||
         version_is_less(version:dllVer2, test_version:"7.5.7600.17034") ||
         version_in_range(version:dllVer2, test_version:"7.5.7600.20000", test_version2:"7.5.7600.21223")||
         version_in_range(version:dllVer2, test_version:"7.5.7601.17000", test_version2:"7.5.7601.17854")||
         version_in_range(version:dllVer2, test_version:"7.5.7601.21000", test_version2:"7.5.7601.22008")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
  }
}
