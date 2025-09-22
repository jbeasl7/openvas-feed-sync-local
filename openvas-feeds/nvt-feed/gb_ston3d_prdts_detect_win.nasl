# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800573");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-06-16 15:11:01 +0200 (Tue, 16 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("StoneTrip Ston3d Products Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script detects the installed version
  of StoneTrip Ston3d products application.");
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

sapVer = registry_get_sz(key:key + "Ston3D Standalone Engine", item:"DisplayVersion");
if(sapVer != NULL)
{
  set_kb_item(name:"Ston3D/Standalone_or_Web/Player/Win/Installed", value:TRUE);
  set_kb_item(name:"Ston3D/Standalone/Player/Win/Ver", value:sapVer);

  register_and_report_cpe(app:"Ston3D Standalone Engine", ver:sapVer,
                          base:"cpe:/a:stonetrip:s3dplayer_standalone:", expr:"^([0-9.]+)");
}

wpVer = registry_get_sz(key:key + "Ston3D Web Player", item:"DisplayVersion");
if(wpVer != NULL)
{
  set_kb_item(name:"Ston3D/Standalone_or_Web/Player/Win/Installed", value:TRUE);
  set_kb_item(name:"Ston3D/Web/Player/Ver", value:wpVer);

  register_and_report_cpe(app:"Ston3D Web Player", ver:wpVer,
                          base:"cpe:/a:stonetrip:s3dplayer_web:", expr:"^([0-9.]+)");
}
