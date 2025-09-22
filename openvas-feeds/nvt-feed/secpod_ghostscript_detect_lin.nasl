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
  script_oid("1.3.6.1.4.1.25623.1.0.900541");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2009-04-28 07:58:48 +0200 (Tue, 28 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Ghostscript Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Ghostscript.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

binaries = ssh_find_file(file_name:"/gs$", useregex:TRUE, sock:sock);
foreach binary(binaries) {

  binary = chomp(binary);
  if(!binary)
    continue;

  vers = ssh_get_bin_version(full_prog_name:binary, version_argv:"--help", ver_pattern:"Ghostscript ([0-9]\.[0-9.]+)", sock:sock);

  if(!isnull(vers[1])) {
    res = vers[max_index(vers)-1];
    if("Ghostscript" >< res && "Artifex Software," >< res) {

      set_kb_item(name:"artifex/ghostscript/lin/detected", value:TRUE);

      cpe = build_cpe(value:vers[1], exp:"^([0-9.]+)", base:"cpe:/a:artifex:ghostscript:");
      if(!cpe)
        cpe = "cpe:/a:artifex:ghostscript";

      register_product(cpe:cpe, location:binary, port:0, service:"ssh-login");

      report = build_detection_report(app:"Ghostscript", version:vers[1], install:binary, cpe:cpe, concluded:vers[max_index(vers)-1]);
      log_message(port:0, data:report);
    }
  }
}

ssh_close_connection();
exit(0);
