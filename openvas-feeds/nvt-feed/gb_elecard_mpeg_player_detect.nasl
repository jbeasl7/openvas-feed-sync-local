# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800510");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-16 16:42:20 +0100 (Mon, 16 Feb 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Elecard MPEG Player Application Version Detection");

  script_category(ACT_GATHER_INFO);

  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This script detects the installed version of Elecard MPEG
  Player application.");

  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Elecard MPEG Player Application Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Elecard")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

keys = registry_enum_keys(key:key);

foreach item(keys)
{
  appName = registry_get_sz(key:key + item, item:"DisplayName");
  if(appName == "Elecard MPEG Player")
  {
    path = registry_get_sz(key:key + item, item:"InstallLocation");
    break;
  }
}
if(!path)
{
  exit(0);
}
path = path + "\MpegPlayer.exe";

eleVer = GetVersionFromFile(file:path, offset:1067429);

if(eleVer != NULL)
{
  set_kb_item(name:"Elecard/Player/Ver", value:eleVer);
  cpe = build_cpe(value:eleVer, exp:"^([0-9.]+)", base:"cpe:/a:elecard:elecard_mpeg_player:");
  if(isnull(cpe))
    cpe = "cpe:/a:elecard:elecard_mpeg_player";

  register_product(cpe: cpe, location: path, port:0, service:"smb-login");
  log_message(data: build_detection_report(app: "Elecard Player",
                                         version: eleVer,
                                         install: path,
                                             cpe: cpe,
                                       concluded: eleVer));

  exit(0);
}

exit(0);
