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
  script_oid("1.3.6.1.4.1.25623.1.0.900969");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2009-10-31 09:54:01 +0100 (Sat, 31 Oct 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("QEMU Version Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of QEMU.");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

qemuName = ssh_find_file(file_name:"/qemu$", useregex:TRUE, sock:sock);

found = FALSE;

foreach binary(qemuName) {
  binary = chomp(binary);
  if(!binary)
    continue;
  qemuVer = ssh_get_bin_version(full_prog_name:binary, sock:sock, version_argv:"-help", ver_pattern:"QEMU PC emulator version ([0-9.]+)");
  if(!isnull(qemuVer[1])){
    set_kb_item(name:"QEMU/Lin/Ver", value:qemuVer[1]);

    cpe = build_cpe(value:qemuVer[1], exp:"^([0-9.]+)", base:"cpe:/a:qemu:qemu:");
    if(!cpe)
      cpe = "cpe:/a:qemu:qemu";

    register_product(cpe:cpe, port:0, location:binary, service:"ssh-login");

    report = build_detection_report(app:"QEMU PC emulator", version:qemuVer[1], install:binary, cpe:cpe, concluded:qemuVer[0]);
    log_message(data:report, port:0);
    found = TRUE;
  }
}

if(!found) {
  qemuName = ssh_find_file(file_name:"/bin/qemu-.+$", useregex:TRUE, sock:sock);

  foreach binary(qemuName) {
    binary = chomp(binary);
    # binaries are the ones from qemu-utils which have different versions and are not part of QEMU itself.
    if(!binary || "qemu-img" >< binary || "qemu-io" >< binary || "qemu-nbd" >< binary)
      continue;

    file = eregmatch(pattern:'.*/([^/]+)', string:binary);
    file = file[1];
    qemuVer = ssh_get_bin_version(full_prog_name:binary, sock:sock, version_argv:"--version", ver_pattern:"(" + file + "|QEMU emulator|QEMU PC emulator) version ([0-9.]+)");

    if(!isnull(qemuVer[2])){
      set_kb_item(name:"QEMU/Lin/Ver", value:qemuVer[2]);

      cpe = build_cpe(value:qemuVer[2], exp:"^([0-9.]+)", base:"cpe:/a:qemu:qemu:");
      if(!cpe)
        cpe = "cpe:/a:qemu:qemu";

      register_product(cpe:cpe, port:0, location:binary, service:"ssh-login");

      report = build_detection_report(app:"QEMU PC emulator", version:qemuVer[2], install:binary, cpe:cpe, concluded:qemuVer[0]);
      log_message(data:report, port:0);
      break;
    }
  }
}

ssh_close_connection();

exit(0);
