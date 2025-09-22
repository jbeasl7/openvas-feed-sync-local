# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800728");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-08 05:49:24 +0100 (Tue, 08 Dec 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Serenity/Mplay Player Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script detects the installed version of Serenity/Mplay
  Audio Player.");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

appKey  = "SOFTWARE\Serenity Audio Player";
appKey2 = "SOFTWARE\Malx media player";
if(!registry_key_exists(key:appKey) && !registry_key_exists(key:appKey2)){
  exit(0);
}

appPath  = registry_get_sz(key:appKey, item:"Install_Dir");
appPath2 = registry_get_sz(key:appKey2, item:"Install_Dir");

if(appPath != NULL)
{
  serenityVer = fetch_file_version(sysPath:appPath, file_name:"serenity.exe");
  if(serenityVer != NULL)
  {
    set_kb_item(name:"Serenity/Audio/Player/Ver", value:serenityVer);

    register_and_report_cpe(app:"Serenity Audio Player", ver:serenityVer, base:"cpe:/a:malsmith:serenity_audio_player:",
                            expr:"^([0-9.]+)", insloc:appPath);
  }
}

if(appPath2 != NULL)
{
  mplayVer = fetch_file_version(sysPath:appPath2, file_name:"mplay.exe");
  if(mplayVer != NULL)
  {
    set_kb_item(name:"Mplay/Audio/Player/Ver", value:mplayVer);

    register_and_report_cpe(app:"Malx media player", ver:mplayVer, base:"cpe:/a:malsmith:serenity_audio_player:",
                            expr:"^([0-9.]+)", insloc:appPath2);
    exit(0);
  }
}
