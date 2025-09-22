# Copyright (C) 2008 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.800019");
  script_version("2021-07-19T10:51:38+0000");
  script_tag(name:"last_modification", value:"2021-07-19 10:51:38 +0000 (Mon, 19 Jul 2021)");
  script_tag(name:"creation_date", value:"2008-10-07 14:21:23 +0200 (Tue, 07 Oct 2008)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Mozilla SeaMonkey Detection (Linux/Unix SSH Login)");
  script_family("Product detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Mozilla SeaMonkey.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

paths = ssh_find_file(file_name:"/(seamonkey|iceape)$", useregex:TRUE, sock:sock);
if(!paths) {
  ssh_close_connection();
  exit(0);
}

foreach bin(paths) {

  #Examples for versions:
  #1.0 Alpha
  #2.0 RC 2
  #2.0.14
  #2.49.4
  #Returned version from binary: Mozilla SeaMonkey 2.49.4
  vers = ssh_get_bin_version(full_prog_name:bin, version_argv:"-v", ver_pattern:"^Mozilla\sSeaMonkey\s([0-9]+\.[0-9.]+(\s(RC\s[0-9]+|Alpha|Beta))?)$");
  if(vers[1]) {

    set_kb_item(name:"Seamonkey/Linux/Ver", value:vers[1]);
    set_kb_item(name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Linux/Installed", value:TRUE);

    cpeVer = str_replace(string:vers[1], find:" ", replace:".");
    cpe = "cpe:/a:mozilla:seamonkey:" + cpeVer;

    register_product(cpe:cpe, location:bin, port:0, service:"ssh-login");
    log_message(data:build_detection_report(app:"Mozilla SeaMonkey",
                                            version:vers[1],
                                            install:bin,
                                            cpe:cpe,
                                            concluded:vers[0]),
                port:0);
  }
}

ssh_close_connection();
exit(0);