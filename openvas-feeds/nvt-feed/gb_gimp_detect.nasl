# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836058");
  script_version("2025-03-26T05:38:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-26 05:38:58 +0000 (Wed, 26 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-03-21 16:12:37 +0530 (Fri, 21 Mar 2025)");
  script_tag(name:"qod_type", value:"registry");
  script_name("GIMP (Windows SMB Login)");
  script_tag(name:"summary", value:"SMB login-based detection of GIMP.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key + item, item:"DisplayName");
  if("GIMP" >< appName)
  {
    gimpVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    gimpPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!gimpPath) {
      gimpPath = "Could not find the install Location from registry";
    }
    if(gimpVer)
    {
      set_kb_item(name:"Gimp/Win/Ver", value:gimpVer);
      set_kb_item(name:"Gimp/Win/detected", value:TRUE);

      register_and_report_cpe( app:"GIMP", ver:gimpVer, concluded:gimpVer,
                           base:"cpe:/a:gimp:gimp:", expr:"^([0-9.]+)",
                           insloc:gimpPath, regService:"smb-login", regPort:0 );
      exit(0);
    }
  }
}

exit(0);
