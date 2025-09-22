# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813821");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-08-10 14:55:05 +0530 (Fri, 10 Aug 2018)");
  script_name("VMware Horizon Client Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  VMware Horizon Client.

  The script logs in via smb, searches registry for VMware Horizon Client
  and gets the version from 'DisplayVersion' string.");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://my.vmware.com");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
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

## same key exist for 32 and 64 bit application
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  vmhrName = registry_get_sz(key:key + item, item:"DisplayName");

  if("VMware Horizon Client" >< vmhrName)
  {
    vmhrVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(vmhrVer)
    {
      vmhrPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!vmhrPath){
        vmhrPath = "Unable to find the install location from registry";
      }

      set_kb_item(name:"VMware/HorizonClient/Win/Ver", value:vmhrVer);

      cpe = build_cpe(value:vmhrVer, exp:"^([0-9.]+)", base:"cpe:/a:vmware:horizon_view_client:");
      if(isnull(cpe))
        cpe = "cpe:/a:vmware:horizon_view_client";

      register_product(cpe:cpe, location:vmhrPath);
      log_message(data: build_detection_report(app:"VMware Horizon Client",
                                                 version: vmhrVer,
                                                 install: vmhrPath,
                                                 cpe: cpe,
                                                 concluded: vmhrVer));
      exit(0);
    }
  }
}
exit(0);
