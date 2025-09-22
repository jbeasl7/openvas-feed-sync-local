# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800553");
  script_version("2025-07-03T05:42:54+0000");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:54 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("ClamAV Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of ClamAV.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

port = kb_ssh_transport();

files = ssh_find_bin(prog_name:"clamscan", sock:sock);
foreach file(files) {

  file = chomp(file);
  if(!file)
    continue;

  vers = ssh_get_bin_version(full_prog_name:file, version_argv:"-V", ver_pattern:"ClamAV ([0-9.]+)", sock:sock);
  if(vers[1]) {

    ssh_close_connection();

    set_kb_item(name:"clamav/detected", value:TRUE);
    set_kb_item(name:"clamav/ssh-login/detected", value:TRUE);
    set_kb_item(name:"clamav/smb-login/port", value:port);

    set_kb_item(name:"clamav/smb-login/" + port + "/installs", value:"0#---#" + file + "#---#" + vers[1] + "#---#" + vers[0]);

    exit(0);
  }
}

ssh_close_connection();

exit(0);
