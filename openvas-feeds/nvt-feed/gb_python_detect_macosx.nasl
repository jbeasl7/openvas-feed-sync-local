# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804633");
  script_version("2021-02-15T14:13:17+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-02-15 14:13:17 +0000 (Mon, 15 Feb 2021)");
  script_tag(name:"creation_date", value:"2014-06-09 16:03:10 +0530 (Mon, 09 Jun 2014)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Python Detection (SSH Login / Mac OS X)");

  script_tag(name:"summary", value:"SSH login-based detection of Python for Mac OS X.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

port = kb_ssh_transport();

pythonSeries = make_list("2.5", "2.6", "2.7", "3.0", "3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "3.7", "3.8", "3.9", "3.10");

found = FALSE;

foreach series(pythonSeries) {
  cmd = "defaults read /Applications/Python\ " + series + "/Python\ Launcher.app/Contents/Info.plist CFBundleShortVersionString";
  version = chomp(ssh_cmd(socket: sock, cmd: cmd));

  if(!version || "does not exist" >< version)
    continue;

  location = "/Applications/Python" + series + "/Python Launcher.app";

  set_kb_item(name: "python/ssh-login/" + port + "/installs", value: "0#---#" + location + "#---#" + version + "#---#" + cmd);
}

if(found) {
  set_kb_item(name: "python/detected", value: TRUE);
  set_kb_item(name: "python/mac-os-x/detected", value: TRUE);
  set_kb_item(name: "python/ssh-login/detected", value: TRUE);
  set_kb_item(name: "python/ssh-login/port", value: port);
}

close(sock);

exit(0);
