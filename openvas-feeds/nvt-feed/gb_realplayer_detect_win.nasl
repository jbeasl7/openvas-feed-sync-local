# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800508");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-18 15:32:11 +0100 (Wed, 18 Feb 2009)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("RealPlayer Application Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of RealNetworks RealPlayer.

The script logs in via smb, searches for RealPlayer in the registry and
gets the path for 'realplayer.exe' file in registry and version from
realplayer.exe file.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
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
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths";
}

## Presently Adobe RoboHelp 64bit application is not available
else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach file (make_list("\RealPlay.exe", "\realplay.exe"))
{
  rpFile = registry_get_sz(key:key + file, item:"Path");
  if(!rpFile)
    continue;
}

if(!rpFile){
  exit(0);
}

if(file =~ "realplay.exe")
{
  oldPath = eregmatch(pattern:"(.*);", string:rpFile);
  if(oldPath && oldPath[0]){
    rpFile =  oldPath[1];
  }
}

rpVer = fetch_file_version(sysPath: rpFile, file_name:"realplay.exe");
if(isnull(rpVer))
   exit(0);

if("RealPlayer Enterprise" >< rpFile)
{
  set_kb_item(name:"RealPlayer/RealPlayer_or_Enterprise/Win/Installed", value:TRUE);
  set_kb_item(name:"RealPlayer-Enterprise/Win/Ver", value:rpVer);
  cpe = build_cpe(value:rpVer, exp:"^([0-9.]+)", base:"cpe:/a:realnetworks:realplayer:" +
                               rpVer + "::enterprise");
}
else
{
  set_kb_item(name:"RealPlayer/RealPlayer_or_Enterprise/Win/Installed", value:TRUE);
  set_kb_item(name:"RealPlayer/Win/Ver", value:rpVer);
  cpe = build_cpe(value:rpVer, exp:"^([0-9.]+)", base:"cpe:/a:realnetworks:realplayer:");
}

if(isnull(cpe))
  cpe = 'cpe:/a:realnetworks:realplayer';

register_product(cpe:cpe, location:rpFile);

log_message(data: build_detection_report(app:"RealNetworks RealPlayer" ,
                                         version: rpVer, install: rpFile, cpe:cpe, concluded:rpVer));
