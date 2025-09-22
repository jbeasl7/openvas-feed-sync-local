# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.809737");
  script_version("2022-10-28T10:12:24+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-10-28 10:12:24 +0000 (Fri, 28 Oct 2022)");
  script_tag(name:"creation_date", value:"2016-12-01 17:27:04 +0530 (Thu, 01 Dec 2016)");
  script_name("FreeRDP Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://www.freerdp.com");

  script_tag(name:"summary", value:"SSH login-based detection of FreeRDP.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

version = "unknown";

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

binFiles = ssh_find_file(file_name:"/xfreerdp$", useregex:TRUE, sock:sock);
if(!binFiles) {
  ssh_close_connection();
  exit(0);
}

foreach executableFile(binFiles) {

  executableFile = chomp(executableFile);
  if(!executableFile)
    continue;

  ftVer = ssh_get_bin_version(full_prog_name:executableFile, sock:sock, version_argv:"--version",
    ver_pattern:"([0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9+]+)?)|com\.freerdp\.client");

  if(!isnull(ftVer[1])) {

    # nb: Required as we might also catch no version at all due to the second pattern above
    if(ftVer[1] =~ "[0-9]+\.[0-9]+\.[0-9]+")
      version = ftVer[1];

    set_kb_item(name:"FreeRDP/Linux/Ver", value:version);

    # nb: The above should be replaced in the future if possible
    set_kb_item(name:"freerdp/detected", value:TRUE);
    set_kb_item(name:"freerdp/ssh-login/detected", value:TRUE);

    cpe = build_cpe(value:version, exp:"^([0-9.]+-?[A-Za-z0-9]+?[+]?[0-9]+?)", base:"cpe:/a:freerdp_project:freerdp:");
    if(!cpe)
      cpe = "cpe:/a:freerdp_project:freerdp";

    register_product(cpe:cpe, location:executableFile, port:0, service:"ssh-login");

    log_message(data:build_detection_report(app:"FreeRDP",
                                            version:version,
                                            install:executableFile,
                                            cpe:cpe,
                                            concluded:ftVer[1]),
                port:0);
    ssh_close_connection();
    exit(0);
  }
}

ssh_close_connection();
exit(0);
