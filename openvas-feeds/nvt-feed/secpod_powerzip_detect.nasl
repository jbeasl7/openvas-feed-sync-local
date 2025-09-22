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
  script_oid("1.3.6.1.4.1.25623.1.0.900490");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2009-03-31 07:06:59 +0200 (Tue, 31 Mar 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("PowerZip Version Detection");

  script_tag(name:"summary", value:"This script finds the installed version of PowerZip.

The script logs in via smb, searches for PowerZip in the registry and gets the
path and version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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
  key_list = make_list("SOFTWARE\Trident Software\PowerZip\");
}

else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Wow6432Node\Trident Software\PowerZip\");
}

if(isnull(key_list)){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Trident Software\PowerZip\")){
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Trident Software\PowerZip\")){
    exit(0);
  }
}

foreach key (key_list)
{
  zipName = registry_get_sz(key:key, item:"Name");
  if("PowerZip" >< zipName)
  {
    zipVer = registry_get_sz(key:key, item:"Version");
    zipPath = registry_get_sz(key:key, item:"Path");
    if(!zipPath){
      zipPath = "Could not determine Install Location";
    }
    if(!zipVer)
    {
      if("Wow6432Node" >< key){
        unKey = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
      } else {
        unKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
      }

      foreach item (registry_enum_keys(key:unKey))
      {
        zipName = registry_get_sz(key:unKey + item, item:"DisplayName");
        if("PowerZip" >< zipName)
        {
          zipVer = registry_get_sz(key:unKey + item, item:"DisplayVersion");
          zipPath = registry_get_sz(key:unKey + item, item:"InstallLocation");
        }
      }
    }
    if(zipVer != NULL)
    {
      set_kb_item(name:"PowerZip/Ver", value:zipVer);
      register_and_report_cpe( app:"Powerzip", ver:zipVer, base:"cpe:/a:powerzip:powerzip:", expr:"^([0-9.]+)", insloc:zipPath );
    }
  }
}
