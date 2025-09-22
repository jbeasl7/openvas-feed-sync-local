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
  script_oid("1.3.6.1.4.1.25623.1.0.900855");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2009-09-23 08:37:26 +0200 (Wed, 23 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("FreeRADIUS Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detects the installed version of FreeRADIUS.");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "FreeRADIUS Version Detection";

radius_sock = ssh_login_or_reuse_connection();
if(!radius_sock)
  exit(0);

foreach name (make_list("radiusd", "freeradius"))
{
  radius_name = ssh_find_bin(prog_name:name, sock:radius_sock);
  foreach binName (radius_name)
  {

    binName = chomp(binName);
    if(!binName)
      continue;

    radius_ver = ssh_get_bin_version(full_prog_name:binName, sock:radius_sock, version_argv:"-v", ver_pattern:"FreeRADIUS Version ([0-9]\.[0-9.]+)");
     if(radius_ver[1] != NULL){
      set_kb_item(name:"FreeRADIUS/Ver", value:radius_ver[1]);
      log_message(data:"FreeRADIUS version " + radius_ver[1] + " running at location " + binName + " was detected on the host");

      cpe = build_cpe(value:radius_ver[1], exp:"^([0-9.]+)", base:"cpe:/a:freeradius:freeradius:");
      if(!isnull(cpe))
        register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);
    }
  }
}
ssh_close_connection();
