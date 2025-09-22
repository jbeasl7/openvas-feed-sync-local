# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900751");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)");
  script_tag(name:"qod_type", value:"registry");
  script_name("XnView Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of XnView.

The script logs in via smb, searches for XnView in the registry and
gets the version from 'DisplayVersion' string in registry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\XnView_is1";
}

else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\XnView_is1";
}

if(isnull(key)){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\XnView_is1"))
{
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\XnView_is1")){
    exit(0);
  }
}

xnviewVer = registry_get_sz(key:key, item:"DisplayVersion");
if(!xnviewVer){
  exit(0);
}

insloc = registry_get_sz(key:key, item:"InstallLocation");
if(!insloc){
  insloc = "Could not find the install location from registry";
}

set_kb_item(name:"XnView/Win/Ver", value:xnviewVer);

cpe = build_cpe(value:xnviewVer, exp:"^([0-9.]+)", base:"cpe:/a:xnview:xnview:");
if(isnull(cpe))
  cpe = "cpe:/a:xnview:xnview";

register_product(cpe:cpe, location:insloc);

log_message(data: build_detection_report(app:"XnView ",
                                         version:xnviewVer,
                                         install:insloc,
                                         cpe:cpe,
                                         concluded:xnviewVer));
