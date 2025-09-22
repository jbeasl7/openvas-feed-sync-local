# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900064");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-12-12 16:11:26 +0100 (Fri, 12 Dec 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-4032");
  script_name("Vulnerability in Microsoft Office SharePoint Server Could Cause Elevation of Privilege (957175)");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-077");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32638");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful attack result in bypassing certain security restrictions by using
  web browser to directly access the vulnerable administrative functionality.");
  script_tag(name:"affected", value:"- Microsoft Search Server 2008

  - Microsoft Office SharePoint Server");
  script_tag(name:"insight", value:"The flaw is due to SharePoint Server does not properly restrict
  access to administrative portions of the application.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS08-077.");
  script_tag(name:"qod_type", value:"registry");
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

# Hotfix 956716 (MS08-077)
if(hotfix_missing(name:"956716") == 0){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(item:"DisplayName", key:key + item);
  if(("Microsoft Office SharePoint Server 2007" >< appName)||
     ("Microsoft Search Server 2008" >< appName))
  {
    dllPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!dllPath){
      exit(0);
    }

    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
    file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                         string:dllPath + "\12.0\Bin\Mssearch.exe");

    dllVer = GetVer(file:file, share:share);
    if(dllVer != NULL)
    {
      if(version_is_less(version:dllVer, test_version:"12.0.6318.5000")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
      exit(0);
    }
  }
}
