# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812742");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2018-01-30 14:45:05 +0530 (Tue, 30 Jan 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("PowerShell Core Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  PowerShell Core.

  The script logs in via smb, searches for 'PowerShell' in the registry
  and gets the version from 'DisplayVersion' string from registry.");

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
    psName = registry_get_sz(key:key + item, item:"DisplayName");

    if("PowerShell" >< psName)
    {
      psVer = registry_get_sz(key:key + item, item:"DisplayVersion");

      psPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!psPath){
        psPath = "Could not find the install location from registry";
      }

      if(psVer)
      {
        set_kb_item(name:"PowerShell/Win/Ver", value:psVer);

        ## New cpe created
        cpe = build_cpe(value:psVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:powershell:");
        if(!cpe)
          cpe = "cpe:/a:microsoft:powershell";

        if("64" >< os_arch && "Wow6432Node" >!< key)
        {
          set_kb_item(name:"PowerShell64/Win/Ver", value:psVer);
          cpe = build_cpe(value:psVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:powershell:x64:");
          if(!cpe)
            cpe = "cpe:/a:microsoft:powershell:x64";
        }

        register_product(cpe:cpe, location:psPath);
        log_message(data: build_detection_report(app:"PowerShell Core", version: psVer,
                                                 install: psPath, cpe:cpe, concluded:psVer));
        exit(0);
      }
    }
  }
}
exit(0);
