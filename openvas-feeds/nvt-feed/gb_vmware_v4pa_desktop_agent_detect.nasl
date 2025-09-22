# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812788");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2018-03-06 11:00:32 +0530 (Tue, 06 Mar 2018)");
  script_name("VMware vRealize Operations Published Applications (V4PA) Desktop Agent Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"SMB login-based detection of VMware vRealize Operations
  Published Applications (V4PA) Desktop Agent.");

  script_tag(name:"qod_type", value:"registry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch)
  exit(0);

if(!registry_key_exists(key:"SOFTWARE\VMware, Inc.\vRealize Operations for Published Apps\Desktop Agent") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\VMware, Inc.\vRealize Operations for Published Apps\Desktop Agent")) {
  exit(0);
}

if("x86" >< os_arch) {
  key_list = make_list("SOFTWARE\VMware, Inc.\vRealize Operations for Published Apps\Desktop Agent");
}

else if("x64" >< os_arch) {
  key_list = make_list("SOFTWARE\VMware, Inc.\vRealize Operations for Published Apps\Desktop Agent",
                       "SOFTWARE\Wow6432Node\VMware, Inc.\vRealize Operations for Published Apps\Desktop Agent");
}

foreach vmkey(key_list) {
  vmVer = registry_get_sz(key:vmkey, item:"ProductVersion");
  vmPath = registry_get_sz(key:vmkey, item:"VMToolsPath");

  if(!vmPath) {
    vmPath = "Could not find the install location from registry";
  }

  if(vmVer) {
    set_kb_item(name:"vmware/V4PA/DesktopAgent/Win/Ver", value:vmVer);

    cpe = build_cpe(value:vmVer, exp:"^([0-9.]+)", base:"cpe:/a:vmware:vrealize_operations_for_published_applications:");
    if(!cpe)
      cpe = "cpe:/a:vmware:vrealize_operations_for_published_applications";

    if("x64" >< os_arch && "Wow6432Node" >!< vmkey) {
      set_kb_item(name:"vmware/V4PA/DesktopAgent64/Win/Ver", value:vmVer);

      cpe = build_cpe(value:vmVer, exp:"^([0-9.]+)", base:"cpe:/a:vmware:vrealize_operations_for_published_applications:x64:");
      if(!cpe)
        cpe = "cpe:/a:vmware:vrealize_operations_for_published_applications:x64";
    }

    register_product(cpe:cpe, location:vmPath, port:0, service:"smb-login");

    log_message(data: build_detection_report(app: "VMware vRealize Operations Published Applications (V4PA) Desktop Agent",
                                             version: vmVer,
                                             install: vmPath,
                                             cpe: cpe,
                                             concluded: vmVer));
  }
}

exit(0);
