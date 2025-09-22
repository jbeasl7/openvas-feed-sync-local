# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810327");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-01-10 11:07:22 +0530 (Tue, 10 Jan 2017)");
  script_name("HPE LoadRunner Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  HPE LoadRunner.

  The script logs in via smb, searches for 'HP LoadRunner' in the
  registry, gets version and installation path information from the registry.");

  script_tag(name:"qod_type", value:"registry");
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

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

foreach item (registry_enum_keys(key:key))
{
  hpName = registry_get_sz(key:key + item, item:"DisplayName");

  if("HP LoadRunner" >< hpName || "HPE LoadRunner" >< hpName)
  {
    hpVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    if(hpVer)
    {
      hpPath = registry_get_sz(key:key + item, item:"InstallLocation");
        if(!hpPath){
          hpPath = "Could not find the install location from registry";
        }

        set_kb_item(name:"HPE/LoadRunner/Win/Ver", value:hpVer);

        cpe = build_cpe(value:hpVer, exp:"^([0-9.]+)", base:"cpe:/a:hp:loadrunner:");
        if(isnull(cpe))
          cpe = "cpe:/a:hp:loadrunner";

        ## 64 bit apps on 64 bit platform
        if("x64" >< os_arch && "Wow6432Node" >!< key)
        {
          set_kb_item(name:"HPE/LoadRunner64/Win/Ver", value:hpVer);

          cpe = build_cpe(value:hpVer, exp:"^([0-9.]+)", base:"cpe:/a:hp:loadrunner:x64:");
          if(isnull(cpe))
            cpe = "cpe:/a:hp:loadrunner:x64";
        }

        register_product(cpe:cpe, location:hpPath);

        log_message(data: build_detection_report(app: "HPE LoadRunner",
                                                 version: hpVer,
                                                 install: hpPath,
                                                 cpe: cpe,
                                                 concluded: hpVer));
    }
  }
}
