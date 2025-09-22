# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801795");
  script_version("2021-02-05T13:29:15+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-02-05 13:29:15 +0000 (Fri, 05 Feb 2021)");
  script_tag(name:"creation_date", value:"2011-06-07 13:29:28 +0200 (Tue, 07 Jun 2011)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Python Detection (SMB Login / Windows)");

  script_tag(name:"summary", value:"SMB login-based detection of Python on Windows.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("host_details.inc");

port = kb_smb_transport();

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch)
  exit(0);

if("x86" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
} else if("x64" >< os_arch) {
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list))
  exit(0);

if(!registry_key_exists(key:"SOFTWARE\Python")) {
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Python")) {
    exit(0);
  }
}

foreach key (key_list) {
  foreach item (registry_enum_keys(key:key)) {
    name = registry_get_sz(key:key + item, item:"DisplayName");

    #The launcher is not tied to a specific version of Python
    if("Python Launcher" >< name) continue;

    # Python 3.10.0a2 Executables (64-bit)
    # Python 2.7.18 Executables (64-bit)
    if(name =~ "Python [0-9a-z.]+ (Executables |)\([0-9]+-bit\)") {
      path = registry_get_sz(key:key + item, item:"DisplayIcon");
      if(!path)
        path = "unknown";
      else
        path = path - "python.exe";

      if(vers = eregmatch(pattern:"Python ([0-9a-z.]+)", string:name)) {
        version = vers[1];

        # nb: The version inside the Key "DisplayVersion" differs quite a lot from
        # the typical Python versioning scheme found in advisories, etc., but we still might need it.
        # Python 2.7.18 -> 2.7.18150
        # Python 3.7.2 -> 3.7.2150.0
        # Python 3.10.0a2 -> 3.10.102.0
        if(full_vers = registry_get_sz(key:key + item, item:"DisplayVersion")) {
          set_kb_item(name:"python/smb-login/full_version", value:full_vers);
        }

        set_kb_item(name:"python/detected", value:TRUE);
        set_kb_item(name:"python/smb-login/detected", value:TRUE);
        set_kb_item(name:"python/smb-login/port", value:port);

        if("x64" >< os_arch && "Wow6432Node" >!< key) {
          set_kb_item(name:"python64/smb-login/detected", value:TRUE);
        } else {
          set_kb_item(name:"python32/smb-login/detected", value:TRUE);
        }

        set_kb_item(name:"python/smb-login/" + port + "/installs", value:"0#---#" + path + "#---#" + version + "#---#" + name);
      }
    }
  }
}

exit(0);
