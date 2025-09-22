# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107127");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-01-17 16:11:25 +0530 (Tue, 17 Jan 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("WinaXe Plus Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  WinaXe Plus.

  The script logs in via smb, searches for WinaXe Plus in the registry and gets the version from 'DisplayVersion' string from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

arch = get_kb_item("SMB/Windows/Arch");
if (!arch) {
  exit(0);
}

if ("x86" >< arch) {
    key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
} else if ("x64" >< arch) {
    key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if (isnull(key_list)) {
  exit(0);
}

foreach key (key_list) {
  foreach item (registry_enum_keys(key:key))   {
   Name = registry_get_sz(key:key + item, item:"DisplayName");

   if ("WinaXe_Plus" >< Name) {
      set_kb_item(name:"Winaxeplus/Win/installed", value:TRUE);
      Ver = registry_get_sz(key:key + item, item:"DisplayVersion");
      Path = registry_get_sz(key:key + item, item:"InstallLocation");

      if (!Path) {
        Path = "Unable to find the install location from registry";
      }

      if (Ver) {
        set_kb_item(name:"winaxeplus/Win/Ver", value:Ver);
        cpe = build_cpe(value:Ver, exp:"^([0-9.]+)", base:"cpe:/a:winaxe:plus:");
        if (isnull(cpe))
          cpe = "cpe:/a:winaxe:plus";

        if ("x64" >< arch && "x86" >!< Path) {
          set_kb_item(name:"winaxeplus/Win/Ver", value:Ver);
          cpe = build_cpe(value:Ver, exp:"^([0-9.]+)", base:"cpe:/a:winaxe:plus:x64:");
          if(isnull(cpe))
            cpe = "cpe:/a:winaxe:plus:x64";
        }

       register_product(cpe:cpe, location:Path);
       log_message(data: build_detection_report(app: "Winaxe Plus",
                                                version: Ver,
                                                install: Path,
                                                cpe: cpe,
                                                concluded: Ver));
      }
    }
  }
}
