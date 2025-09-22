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
  script_oid("1.3.6.1.4.1.25623.1.0.900191");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2009-01-23 16:33:16 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("VUPlayer Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script detect the installed version of VUPlayernd.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "VUPlayer Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VUPlayer";
vuplayerName = registry_get_sz(key:key, item:"DisplayName");
if(!vuplayerName){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Player";
  vuplayerName = registry_get_sz(key:key, item:"DisplayName");
}

if(vuplayerName =~ "^(VUPlayer|Player)")
{
  exePath = registry_get_sz(key:key, item:"UninstallString");
  if(!exePath){
    exit(0);
  }

  exePath = ereg_replace(pattern:'"', replace:"", string:exePath);
  exePath = exePath - "Uninstall.exe" + vuplayerName + ".exe";

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exePath);

  vuplayerVer = GetVer(file:file, share:share);
  if(vuplayerVer != NULL){
    set_kb_item(name:"VUPlayer/Version", value:vuplayerVer);
    log_message(data:"VUPlayer version " + vuplayerVer + " running at " +
                       "location " + exePath +  " was detected on the host");

    cpe = build_cpe(value:vuplayerVer, exp:"^([0-9.]+)", base:"cpe:/a:vuplayer:vuplayer:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

  }
}
