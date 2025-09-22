# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902626");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-09-22 10:24:03 +0200 (Thu, 22 Sep 2011)");
  script_cve_id("CVE-2010-3243", "CVE-2010-3324");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Microsoft SharePoint SafeHTML Information Disclosure Vulnerabilities (2412048)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2412048");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42467");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43703");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-072");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to gain sensitie
  information via a specially crafted script using SafeHTML.");
  script_tag(name:"affected", value:"- Microsoft Office SharePoint Server 2007 Service Pack 2

  - Microsoft Windows SharePoint Services 3.0 Service Pack 2");
  script_tag(name:"insight", value:"Multiple flaws are due to the way SafeHTML function sanitizes HTML content.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS10-072.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

## MS10-072 Hotfix
if(hotfix_missing(name:"2345304") == 1)
{
  ## Microsoft SharePoint Server 2007
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

  if(registry_key_exists(key:key))
  {
    foreach item (registry_enum_keys(key:key))
    {
      appName = registry_get_sz(item:"DisplayName", key:key + item);
      if("Microsoft Office SharePoint Server 2007" >< appName)
      {
        dllPath =  registry_get_sz(item:"BinPath",
                              key:"SOFTWARE\Microsoft\Office Server\12.0");

        if(dllPath)
        {
          dllPath = dllPath + "web server extensions\12\ISAPI";
          vers  = fetch_file_version(sysPath:dllPath,
                                   file_name:"Microsoft.office.server.dll");
          if(vers)
          {
            if(version_is_less(version:vers, test_version:"12.0.6539.5000"))
            {
              report = report_fixed_ver(installed_version:vers, fixed_version:"12.0.6539.5000", install_path:dllPath);
              security_message(port: 0, data: report);
              exit(0);
            }
          }
        }
      }
    }
  }
}

if(hotfix_missing(name:"2345212") == 0){
  exit(0);
}

## Microsoft Windows SharePoint Services
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  srvcName = registry_get_sz(item:"DisplayName", key:key + item);
  if("Microsoft Windows SharePoint Services" >< srvcName)
  {
    dllPath =  registry_get_sz(item:"SharedFilesDir",
               key:"SOFTWARE\Microsoft\Shared Tools");

    if(!dllPath){
      exit(0);
    }

    dllPath = dllPath + "web server extensions\12\BIN";
    dllVer  = fetch_file_version(sysPath:dllPath, file_name:"Onetutil.dll");

    if(!dllVer){
      exit(0);
    }

    if(version_is_less(version:dllVer, test_version:"12.0.6545.5002"))
    {
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"12.0.6545.5002", install_path:dllPath);
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
