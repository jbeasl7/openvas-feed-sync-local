# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.810611");
  script_version("2021-02-08T13:19:59+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-02-08 13:19:59 +0000 (Mon, 08 Feb 2021)");
  script_tag(name:"creation_date", value:"2017-03-10 12:18:44 +0530 (Fri, 10 Mar 2017)");
  script_name("Adobe Flash Player Within Microsoft IE and Edge Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_ms_ie_detect.nasl", "gb_microsoft_edge_detect.nasl");
  script_mandatory_keys("MS/IE_or_EDGE/Installed");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of Adobe Flash Player within Microsoft
  Internet Explorer (IE) and Edge.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch)
  exit(0);

sysPath = smb_get_systemroot();
if(!sysPath)
  exit(0);

if("x86" >< os_arch) {
  fileVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Flashplayerapp.exe");
  insloc = sysPath + "\System32";
} else if("x64" >< os_arch) {
  fileVer = fetch_file_version(sysPath:sysPath, file_name:"SysWOW64\Flashplayerapp.exe");
  insloc = sysPath + "\SysWOW64";
}

# nb: Exit if 'Flashplayerapp.exe' version not available
if(!fileVer)
  exit(0);

# nb: Both IE and Edge are using same flashplayer file. Either one can be used to set version.
ie = get_kb_item("MS/IE/Installed");
if(ie) {
  set_kb_item(name:"adobe/flash_player/detected", value:TRUE);
  set_kb_item(name:"AdobeFlashPlayer/IE/Ver", value:fileVer);
  set_kb_item(name:"AdobeFlash/IE_or_EDGE/Installed", value:TRUE);
  base_cpe = "cpe:/a:adobe:flash_player_internet_explorer";
} else {
  # nb: Both IE and Edge can be installed at same time but both uses same file
  edge = get_kb_item("MS/Edge/Installed");
  if(edge) {
    set_kb_item(name:"adobe/flash_player/detected", value:TRUE);
    set_kb_item(name:"AdobeFlashPlayer/EDGE/Ver", value:fileVer);
    set_kb_item(name:"AdobeFlash/IE_or_EDGE/Installed", value:TRUE);
    base_cpe = "cpe:/a:adobe:flash_player_edge";
  }
}

cpe = build_cpe(value:fileVer, exp:"^([0-9.]+)", base:base_cpe + ":");
if(!cpe)
  cpe = base_cpe;

register_product(cpe:cpe, location:insloc, port:0, service:"smb-login");

log_message(data:build_detection_report(app:"Adobe Flash Player within IE/Edge",
                                        version:fileVer,
                                        install:insloc,
                                        cpe:cpe,
                                        concluded:fileVer));
exit(0);
