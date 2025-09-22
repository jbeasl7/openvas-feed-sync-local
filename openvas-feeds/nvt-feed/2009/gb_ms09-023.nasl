# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900568");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-06-10 20:01:05 +0200 (Wed, 10 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-0239");
  script_name("Microsoft Windows Search Script Execution Vulnerability (963093)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/963093");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35220");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-023");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Remote attackers could exploit this issue to obtain sensitive information
  or access to data on the affected system by convincing a user to download
  a crafted file to a specific location, and then open an application that
  loads the file.");
  script_tag(name:"affected", value:"- Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior");
  script_tag(name:"insight", value:"The flaw is caused because the search function does not properly restrict the
  environment within which scripts execute, which could allow sensitive
  information disclosure.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-023.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3) <= 0){
  exit(0);
}

if(hotfix_missing(name:"963093") == 0){
  exit(0);
}

searchName = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                 "\Uninstall\KB940157", item:"DisplayName");

if("Windows Search 4.0" ><  searchName && searchName)
{
  sysPath = smb_get_systemroot();
  if(!sysPath){
    exit(0);
  }

  exeVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Spupdsvc.exe");
  if(exeVer)
  {
    if(version_is_less(version:exeVer, test_version:"6.3.15.0")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
