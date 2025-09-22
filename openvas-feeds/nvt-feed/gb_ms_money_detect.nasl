# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800217");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-01-08 14:06:04 +0100 (Thu, 08 Jan 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Money Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of Microsoft Money on Windows.

  The script logs in via smb, searches for Microsoft Money in the registry
  and gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
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

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

if("x86" >< osArch){
  key_list = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< osArch){
 key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                      "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");

}

foreach key (key_list)
{
   foreach item (registry_enum_keys(key:key))
   {
     if("Microsoft Money" >< registry_get_sz(key:key + item, item:"DisplayName"))
     {
      name = registry_get_sz(key:key + item, item:"DisplayName");

      InstallPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!InstallPath){
        InstallPath = "Could not find the install location from registry";
      }

      ver = eregmatch(pattern:"Microsoft Money ([0-9]+)", string:name);
      if(ver[1] != NULL)
      {

        set_kb_item(name:"MS/Money/Win/Installed", value:TRUE);

        ## 64 bit apps on 64 bit platform
        if("x64" >< osArch && "Wow6432Node" >!< key) {
          set_kb_item(name:"MS/Money64/Win/Version", value:ver[1]);
          register_and_report_cpe( app:"Microsoft Money", ver:ver[1], base:"cpe:/a:microsoft:money:x64:", expr:"^([0-9]+)", insloc: InstallPath );
        } else {
          set_kb_item(name:"MS/Money/Win/Version", value:ver[1]);
          register_and_report_cpe( app:"Microsoft Money", ver:ver[1], base:"cpe:/a:microsoft:money:", expr:"^([0-9]+)", insloc: InstallPath );
        }
      }
    }
  }
}
