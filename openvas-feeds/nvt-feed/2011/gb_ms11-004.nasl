# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901183");
  script_version("2025-03-05T05:38:52+0000");
  script_cve_id("CVE-2010-3972");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-02-09 17:14:46 +0100 (Wed, 09 Feb 2011)");
  script_name("Internet Information Services (IIS) FTP Service Remote Code Execution Vulnerability (2489256)");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/842372");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45542");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15803/");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1024921");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/3305");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a denial of
  service and possibly execute arbitrary code via a crafted FTP request that
  triggers memory corruption.");

  script_tag(name:"affected", value:"- Microsoft Internet Information Services (IIS) version 7.0 on Microsoft Windows Vista/2008 server Service Pack 2 and prior

  - Microsoft Internet Information Services (IIS) version 7.5 on Microsoft Windows 7 Service Pack 1 and prior");

  script_tag(name:"insight", value:"The flaw is due to a boundary error when encoding Telnet IAC
  characters in a FTP response. This can be exploited without authenticating
  to the FTP service to cause a heap-based buffer overflow by sending an overly
  long, specially crafted FTP request.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-004.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-004");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

## MS11-004 Hotfix (2489256)
if(hotfix_missing(name:"2489256") == 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\inetsrv\ftpsvc.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_in_range(version:dllVer, test_version:"7.0", test_version2:"7.0.6545.14978")||
     version_in_range(version:dllVer, test_version:"7.5.7600.0", test_version2:"7.5.7600.14977")||
     version_in_range(version:dllVer, test_version:"7.5.7055.0", test_version2:"7.5.7055.14309")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win7:2) > 0)
{
  if(version_is_less(version:dllVer, test_version:"7.5.7600.16748") ||
     version_in_range(version:dllVer, test_version:"7.5.7600.20000", test_version2:"7.5.7600.20887")||
     version_in_range(version:dllVer, test_version:"7.5.7601.17000", test_version2:"7.5.7601.17549")||
     version_in_range(version:dllVer, test_version:"7.5.7601.21000", test_version2:"7.5.7601.21648")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
