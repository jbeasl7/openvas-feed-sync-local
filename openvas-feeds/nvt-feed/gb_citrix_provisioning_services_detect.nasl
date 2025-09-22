# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802220");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-07-13 17:31:13 +0200 (Wed, 13 Jul 2011)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Citrix Provisioning Services Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of Citrix Provisioning
Services.

The script logs in via smb, searches for Citrix Provisioning Services in the
registry and gets the version from 'DisplayVersion' string in registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
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
if (! os_arch ){
  exit (0);
}

if ("x86" >< os_arch) {
    key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if ("x64" >< os_arch) {
   key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if (isnull(key_list)){
    exit (0);
}

foreach key (key_list)
{
    foreach item (registry_enum_keys(key:key))
    {
      appName = registry_get_sz(key:key + item, item:"DisplayName");
      if("Citrix Provisioning Services" >< appName || (appName =~ "Citrix ([0-9.]+) LTSR" && "Provisioning Services">< appName))
      {
        appVer = registry_get_sz(key:key + item, item:"DisplayVersion");
        if(appVer)
        {
          cpsPath = registry_get_sz(key:key + item, item:"InstallLocation");
          if(!cpsPath){
            cpsPath = "Could not find the install path from registry";
          }

          set_kb_item(name:"Citrix/Provisioning/Services/Ver", value:appVer);
          if (appName =~ "Citrix ([0-9.]+) LTSR"){
            set_kb_item(name:"Citrix/Provisioning/Services/model", value:"LTSR");
          }
          set_kb_item(name:"Citrix/Provisioning/Services/path", value:cpsPath);

          cpe = build_cpe(value: appVer, exp:"^([0-9.]+)", base:"cpe:/a:citrix:citrix_provisioning_server:");
          if(isnull(cpe))
             cpe = 'cpe:/a:citrix:citrix_provisioning_server';

          if("x64" >< os_arch)
          {
            set_kb_item(name:"Citrix/Provisioning/Services64/Ver", value:appVer);
            set_kb_item(name:"Citrix/Provisioning/Services64/path", value:cpsPath);

            cpe = build_cpe(value: appVer, exp:"^([0-9.]+)", base:"cpe:/a:citrix:citrix_provisioning_server:x64:");
            if(isnull(cpe))
               cpe = 'cpe:/a:citrix:citrix_provisioning_server:x64';
          }

          register_product(cpe:cpe, location:cpsPath);

          log_message(data: build_detection_report(app: appName,
                                               version: appVer,
                                               install: cpsPath,
                                               cpe: cpe,
                                               concluded: appVer));
     }
   }
 }
}
