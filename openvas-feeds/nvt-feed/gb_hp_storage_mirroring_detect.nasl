# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801356");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-06-15 06:05:27 +0200 (Tue, 15 Jun 2010)");
  script_name("HP StorageWorks Storage Mirroring Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Detects the installed version of HP StorageWorks Storage Mirroring on Windows.

  The script logs in via smb, searches for HP Storage Mirroring in the
  registry and gets the version.");

  script_tag(name:"qod_type", value:"registry");

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

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Windows\CurrentVersion\Uninstall\");
}

foreach key( key_list ) {

  foreach item( registry_enum_keys( key:key ) )
  {
    hpsmName  = registry_get_sz(key:key + item, item:"DisplayName");

    if("HP Storage Mirroring" >< hpsmName)
    {
      hpsmVer = registry_get_sz(key:key + item, item:"DisplayVersion");

      if(hpsmVer != NULL)
      {
        insLoc = registry_get_sz(key:key + item, item:"InstallLocation");
        if(!insLoc){
          insLoc = "Could not find the install location from registry";
        }

        set_kb_item(name:"HP/SWSM/Installed", value:TRUE);

        if("64" >< os_arch && "Wow6432Node" >!< key) {
          set_kb_item(name:"HP/SWSM64/Ver", value:hpsmVer);
          register_and_report_cpe( app:hpsmName, ver:hpsmVer, concluded:hpsmVer, base:"cpe:/a:hp:storageworks_storage_mirroring:x64:", expr:"^([0-9.]+)", insloc:insLoc );
        } else {
          set_kb_item(name:"HP/SWSM/Ver", value:hpsmVer);
          register_and_report_cpe( app:hpsmName, ver:hpsmVer, concluded:hpsmVer, base:"cpe:/a:hp:storageworks_storage_mirroring:", expr:"^([0-9.]+)", insloc:insLoc );
        }
      }
    }
  }
}
