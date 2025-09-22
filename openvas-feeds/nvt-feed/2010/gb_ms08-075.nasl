# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801483");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-12-14 06:32:32 +0100 (Tue, 14 Dec 2010)");
  script_cve_id("CVE-2008-4268", "CVE-2008-4269");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_name("Microsoft Windows Search Remote Code Execution Vulnerability (959349)");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2008/3387");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32651");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32652");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-075");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attackers attackers to execute
  arbitrary code.");
  script_tag(name:"affected", value:"- Microsoft Windows Vista Service Pack 1 and prior

  - Microsoft Windows Server 2008 Service Pack 1 and prior");
  script_tag(name:"insight", value:"The flaws are due to

  - an error in Windows Explorer that does not correctly free memory when
    saving Windows Search files.

  - an error in Windows Explorer that does not correctly interpret
    parameters when parsing the search-ms protocol.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS08-075.");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");



if(hotfix_check_sp(winVista:2, win2008:2) <= 0){
  exit(0);
}

if(hotfix_missing(name:"958624") == 1)
{
  sysPath = smb_get_system32root();
  if(sysPath)
  {
    dllVer = fetch_file_version(sysPath:sysPath, file_name:"shell32.dll");
    if(dllVer)
    {
      if(hotfix_check_sp(winVista:2) > 0)
      {
        SP = get_kb_item("SMB/WinVista/ServicePack");
        if("Service Pack 1" >< SP)
        {
          if(version_is_less(version:dllVer, test_version:"6.0.6001.18167")){
            report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6001.18167", install_path:sysPath);
            security_message(port: 0, data: report);
          }
          exit(0);
        }
      }

      else if(hotfix_check_sp(win2008:2) > 0)
      {
        SP = get_kb_item("SMB/Win2008/ServicePack");
        if("Service Pack 1" >< SP)
        {
          if(version_is_less(version:dllVer, test_version:"6.0.6001.18167")){
            report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6001.18167", install_path:sysPath);
            security_message(port: 0, data: report);
          }
          exit(0);
        }
      }
    }
  }
}
