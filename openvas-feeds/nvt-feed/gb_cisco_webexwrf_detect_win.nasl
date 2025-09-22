# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107068");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-10-25 11:19:11 +0530 (Tue, 25 Oct 2016)");

  script_tag(name:"qod_type", value:"registry");

  script_name("Cisco WebEx Recording Format (WRF) Player Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of Cisco WebEx Recording Format (WRF) Player.

The script logs in via smb, searches for Cisco WebEx Recording Format (WRF) Player in the registry and gets the
version from 'DisplayVersion' string from registry.");

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

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list)){
  exit(0);
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
   wpName = registry_get_sz(key:key + item, item:"DisplayName");

   if("WebEx Recorder and Player" >< wpName)
    {

      wpVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      wpPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!wpPath){
        wpPath = "Unable to find the install location from registry";
      }

      if(wpVer)
      {
        set_kb_item(name:"Cisco/Wrfplayer/Win/Ver", value:wpVer);
#       cpe = "cpe:/a:cisco:webex_wrf_player:" + wpVer;

        cpe = build_cpe(value:wpVer, exp:"^([0-9.]+)", base:"cpe:/a:cisco:webex_wrf_player:");
        if(isnull(cpe))
          cpe = "cpe:/a:cisco:webex_wrf_player";

        if("x64" >< os_arch && "x86" >!< wpPath)
        {
          set_kb_item(name:"Cisco/Wrfplayer64/Win/Ver", value:wpVer);
#         cpe = "cpe:/a:cisco:webex_wrf_player:" + wpVer + "::~~~~x64~";
          cpe = build_cpe(value:wpVer, exp:"^([0-9.]+)", base:"cpe:/a:cisco:webex_wrf_player:x64:");
          if(isnull(cpe))
            cpe = "cpe:/a:cisco:webex_wrf_player:x64";
        }

       register_product(cpe:cpe, location:wpPath);
       log_message(data: build_detection_report(app: "Cisco Webex WRF Player",
                                                version: wpVer,
                                                install: wpPath,
                                                cpe: cpe,
                                                concluded: wpVer));
      }
    }
  }
}

exit(0);
