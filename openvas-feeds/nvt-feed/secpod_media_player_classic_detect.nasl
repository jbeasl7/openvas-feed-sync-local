# Copyright (C) 2009 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900947");
  script_version("2022-05-25T07:40:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-05-25 07:40:23 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2009-09-18 08:01:03 +0200 (Fri, 18 Sep 2009)");
  script_name("Gabset Media Player Classic Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This script detects the installed version of Gabset Media Player
  Classic.

  The script logs in via smb, searches for Media Player Classic in the registry,
  gets the version from registry.");

  script_tag(name:"qod_type", value:"executable_version");

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
  key_list = make_list("SOFTWARE\Gabest\Media Player Classic\");
}
else if("x64" >< os_arch){
  key_list = make_list("SOFTWARE\Wow6432Node\Gabest\Media Player Classic\");
}

if(isnull(key_list)){
  exit(0);
}

foreach key(key_list){

  mpcPath = registry_get_sz(key:key, item:"ExePath");

  if(mpcPath){

    cpath_list = split(mpcPath, sep:"\", keep:FALSE);
    exeName = cpath_list[max_index(cpath_list)-1];
    mpcVer = fetch_file_version(sysPath:mpcPath - exeName, file_name:exeName);
    mpcPath = mpcPath - exeName ;

    if(!mpcVer) mpcVer = "unknown";

    if(mpcVer) {
      set_kb_item(name:"MediaPlayerClassic/Ver", value:mpcVer);

      cpe = build_cpe(value:mpcVer, exp:"^([0-9.]+)", base:"cpe:/a:rob_schultz:media_player_classic:");
      if(isnull(cpe))
        cpe = "cpe:/a:rob_schultz:media_player_classic";

      register_product(cpe:cpe, location:mpcPath);

      log_message(data:build_detection_report(app:"Gabest Media Player Classic",
                                              version:mpcVer,
                                              install:mpcPath,
                                              cpe:cpe,
                                              concluded:mpcVer));
    }
  }
}
