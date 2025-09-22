# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902724");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)");
  script_cve_id("CVE-2011-3142");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46757");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("WellinTech KingView 'KVWebSvr.dll' ActiveX Control Heap Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"insight", value:"The flaw exists due to error in 'KVWebSvr.dll' file, when 'ValidateUser'
  method in an ActiveX component called with a specially crafted argument to cause a stack-based buffer overflow.");

  script_tag(name:"summary", value:"KingView is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution", value:"Upgrade KVWebSrv.dll file version to 65.30.2010.18019.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the application. Failed attacks will cause
  denial-of-service conditions.");

  script_tag(name:"affected", value:"KingView version 6.53 and 6.52");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion"))
  exit(0);

if(!registry_key_exists(key:"SOFTWARE\WellinControl Technology Development Co.,Ltd."))
  exit(0);

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key))
  exit(0);

foreach item(registry_enum_keys(key:key))
{
  kvName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Kingview" >< kvName)
  {
    kvVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(kvVer!= NULL)
    {
      if(version_is_equal(version:kvVer, test_version:"6.52") ||
         version_is_equal(version:kvVer, test_version:"6.53"))
      {
        dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                          item:"ProgramFilesDir");
        if(dllPath)
        {
          dllVer = fetch_file_version(sysPath:dllPath, file_name:"Kingview\KVWebSvr.dll");
          {
            if(version_is_less(version:dllVer, test_version:"65.30.2010.18019")){
               security_message( port: 0, data: "The target host was found to be vulnerable" );
            }
          }
        }
      }
    }
  }
}
