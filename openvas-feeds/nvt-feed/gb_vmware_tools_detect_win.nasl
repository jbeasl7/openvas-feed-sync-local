# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809030");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-09-02 13:07:24 +0530 (Fri, 02 Sep 2016)");
  script_name("VMware Tools Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  VMware Tools.

  The script logs in via smb, searches registry for VMware Tools
  and gets the version from 'DisplayVersion' string.");

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

if(!registry_key_exists(key:"SOFTWARE\VMware, Inc.\VMware Tools") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\VMware, Inc.\VMware Tools")){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");

}

if(isnull(key_list)){
  exit(0);
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    vmtoolName = registry_get_sz(key:key + item, item:"DisplayName");

    if("VMware Tools" >< vmtoolName)
    {
      vmtoolVer = registry_get_sz(key:key + item, item:"DisplayVersion");

      if(vmtoolVer)
      {
        vmtoolPath = registry_get_sz(key:key + item, item:"InstallLocation");
        if(!vmtoolPath){
          vmtoolPath = "Unable to find the install location from registry";
        }

        set_kb_item(name:"VMwareTools/Win/Ver", value:vmtoolVer);

        cpe = build_cpe(value:vmtoolVer, exp:"^([0-9.]+)", base:"cpe:/a:vmware:tools:");
        if(isnull(cpe))
          cpe = "cpe:/a:vmware:tools";

        register_product(cpe:cpe, location:vmtoolPath);
        log_message(data: build_detection_report(app: "VMware Tools",
                                                 version: vmtoolVer,
                                                 install: vmtoolPath,
                                                 cpe: cpe,
                                                 concluded: vmtoolVer));
        exit(0);
      }
    }
  }
}
exit(0);
