# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800158");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-01-28 16:24:05 +0100 (Thu, 28 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("South River WebDrive Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script detects the installed South River WebDrive.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "South River WebDrive Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## South River Web Drive Application confirmation
if(!registry_key_exists(key:"SOFTWARE\South River Technologies\WebDrive")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  webDrive = registry_get_sz(key:key + item, item:"DisplayName");
  if("WebDrive" >< webDrive)
  {
    webDriveVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if( webDriveVer != NULL)
    {
       set_kb_item(name:"SouthRiverWebDrive/Win/Ver", value:webDriveVer);
       log_message(data:"South River WebDrive version " + webDriveVer +
                         " was detected on the host");

       cpe = build_cpe(value:webDriveVer, exp:"^([0-9.]+)", base:"cpe:/a:south_river_technologies:webdrive:");
       if(!isnull(cpe))
          register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

    }
    exit(0);
  }
}
