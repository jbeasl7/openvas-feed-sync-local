# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808533");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2016-07-05 11:35:48 +0530 (Tue, 05 Jul 2016)");
  script_name("Symantec Antivirus Engine Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of Symantec
  Antivirus Engine.
  The script logs in via smb, searches for string 'Symantec Antivirus Engine' in
  the registry and reads the version information from registry.");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

key = "SOFTWARE\Symantec\SharedDefs\";
if(isnull(key)){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< os_arch){
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(isnull(key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  symName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Symantec Endpoint Protection Manager" >< symName)
  {
    symPath = registry_get_sz(key:key + item, item:"InstallLocation");

    if(!symPath){
      symPath = "Could not find the install location from registry";
    }

    key_list = make_list("SOFTWARE\Symantec\SharedDefs\SymcData-spcVirDef32Reduced\",
                         "SOFTWARE\Symantec\SharedDefs\SymcData-spcVirDef32\",
                         "SOFTWARE\Symantec\SharedDefs\SymcData-spcVirDef64Reduced\",
                         "SOFTWARE\Symantec\SharedDefs\SymcData-spcVirDef64\");
    foreach key1(key_list)
    {
      appPath = registry_get_sz(key:key1, item:"SesmInstallApp");
      if(appPath){
        break;
      }
    }

    symVer = fetch_file_version(sysPath:appPath, file_name:"naveng32.dll");
    if(symVer)
    {
      set_kb_item(name:"Symantec/Antivirus/Engine/Ver", value:symVer);

      register_and_report_cpe( app:"Symantec Antivirus Engine", ver:symVer, concluded:symVer, base:"cpe:/a:symantec:anti-virus_engine:", expr:"^([0-9.]+)", insloc:symPath );
    }
    exit(0);
  }
}
