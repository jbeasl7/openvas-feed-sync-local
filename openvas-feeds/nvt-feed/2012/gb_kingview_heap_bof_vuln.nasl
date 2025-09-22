# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802550");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2011-4536");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-01-02 14:11:32 +0530 (Mon, 02 Jan 2012)");
  script_name("WellinTech KingView 'HistoryServer.exe' Heap Based Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-351/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51159");

  script_tag(name:"insight", value:"The flaw is due to an error in the 'nettransdll.dll' module of the
  'HistorySvr' component when processing a packet containing opcode 3. This can
  be exploited to cause a heap-based buffer overflow via a specially crafted packet sent to TCP port 777.");

  script_tag(name:"summary", value:"KingView is prone to heap based buffer overflow vulnerability.");

  script_tag(name:"solution", value:"Apply the patch.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the application. Failed attacks will cause  denial-of-service conditions.");

  script_tag(name:"affected", value:"KingView version 6.53 and 65.30.2010.18018");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

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
      if(version_is_equal(version:kvVer, test_version:"6.53"))
      {
        dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                          item:"ProgramFilesDir");
        if(dllPath)
        {
          dllVer = fetch_file_version(sysPath:dllPath, file_name:"Kingview\nettransdll.dll");
          {
            if(version_is_less(version:dllVer, test_version:"65.30.2010.18018"))
            {
              report = report_fixed_ver(installed_version:dllVer, fixed_version:"65.30.2010.18018");
              security_message(port:0, data:report);
              exit(0);
            }
          }
        }
      }
    }
  }
}
