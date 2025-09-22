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
  script_oid("1.3.6.1.4.1.25623.1.0.900556");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2009-06-01 09:35:57 +0200 (Mon, 01 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("CTorrent/Enhanced CTorrent Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script retrieves CTorrent/Enhanced
  CTorrent version.");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

getPath = ssh_find_bin(prog_name:"ctorrent", sock:sock);
foreach binaryFile (getPath)
{

  binaryFile = chomp(binaryFile);
  if(!binaryFile)
    continue;

  ctorrentVer = ssh_get_bin_version(full_prog_name:binaryFile, version_argv:"-h", ver_pattern:"(C|c)(T|t)orrent (dnh)?([0-9.]+)", sock:sock);
  if(ctorrentVer[4] != NULL)
  {
    if("dnh" >< ctorrentVer[3]){
      set_kb_item(name:"CTorrent/CTorrent_or_Enhanced/Installed", value:TRUE);
      set_kb_item(name:"Enhanced/CTorrent/Ver", value:ctorrentVer[4]);

      register_and_report_cpe(app:"CTorrent/Enhanced CTorrent", ver:ctorrentVer[4], base:"cpe:/a:rahul:dtorrent:", expr:"^([0-9.]+)", insloc:binaryFile);
    } else {
      set_kb_item(name:"CTorrent/CTorrent_or_Enhanced/Installed", value:TRUE);
      set_kb_item(name:"CTorrent/Ver", value:ctorrentVer[4]);

      register_and_report_cpe(app:"CTorrent/Enhanced CTorrent", ver:ctorrentVer[4], base:"cpe:/a:rahul:dtorrent:", expr:"^([0-9.]+)", insloc:binaryFile);
    }
  }
  ssh_close_connection();
  exit(0);
}
ssh_close_connection();
