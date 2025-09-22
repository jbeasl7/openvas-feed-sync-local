# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902084");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-06-25 16:56:31 +0200 (Fri, 25 Jun 2010)");
  script_name("Adobe InDesign Version Detection");
  script_tag(name:"summary", value:"Detects the installed version of
  Adobe InDesign.

  The script logs in via smb, searches for Adobe InDesign in the registry
  and gets the version from 'DisplayVersion' string from registry.");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
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

if(!registry_key_exists(key:"SOFTWARE\Adobe\InDesign") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\Adobe\InDesign")){
  exit(0);
}

if("x86" >< os_arch){
  key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch)
{
 key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                      "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    adName = registry_get_sz(key:key + item, item:"DisplayName");
    if("Adobe InDesign" >< adName)
    {
      adPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!adPath){
        adPath = "Could not find the install location from registry";
      }

      adVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(!isnull(adVer))
      {
        tmp_version = adName + " " + adVer;
        set_kb_item(name:"Adobe/InDesign/Ver", value:tmp_version);
        log_message(data:adName + " version " + adVer + " installed at location " +
                       adPath + " was detected on the host");

        cpe = build_cpe(value:adVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:indesign_server:");
        if(!cpe)
          cpe = "cpe:/a:adobe:indesign_server";
        if("x64" >< os_arch && "Wow6432Node" >!< key)
        {

          set_kb_item(name:"Adobe/InDesign/Ver64/Win/Ver", value:adVer);

          cpe = build_cpe(value:adVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:indesign_server:x64:");
          if(!cpe)
            cpe = "cpe:/a:adobe:indesign_server:x64";
        }

        register_product(cpe:cpe, location:adPath);
        log_message(data: build_detection_report(app: "Adobe Indesign",
                                                 version: adVer,
                                                 install: adPath,
                                                 cpe: cpe,
                                                 concluded: adVer));

      }
    }
  }
}
