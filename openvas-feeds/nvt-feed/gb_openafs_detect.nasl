# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808072");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2016-06-08 12:16:58 +0530 (Wed, 08 Jun 2016)");
  script_name("OpenAFS Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  OpenAFS.

  The script logs in via smb, searches for 'OpenAFS' in the registry and
  gets the version from registry.");

  script_tag(name:"qod_type", value:"registry");

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

## Key is same for 32 bit and 64 bit platform
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  afsName = registry_get_sz(key:key + item, item:"DisplayName");

  if("OpenAFS" >< afsName)
  {
    afsVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    afsPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!afsPath){
      afsPath = "Could not find the install location from registry";
    }

    if(afsVer)
    {

      set_kb_item(name:"OpenAFS/Win/Installed", value:TRUE);

      if("64" >< os_arch) {
        set_kb_item(name:"OpenAFS/Win64/Ver", value:afsVer);
        register_and_report_cpe( app:afsName, ver:afsVer, base:"cpe:/a:openafs:openafs:x64:", expr:"^([0-9.]+)", insloc:afsPath );
      } else {
        set_kb_item(name:"OpenAFS/Win/Ver", value:afsVer);
        register_and_report_cpe( app:afsName, ver:afsVer, base:"cpe:/a:openafs:openafs:", expr:"^([0-9.]+)", insloc:afsPath );
      }
    }
    exit(0);
  }
}
