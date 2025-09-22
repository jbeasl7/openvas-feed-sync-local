# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14315");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("CFEngine Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of CFEngine.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

paths = ssh_find_bin(prog_name:"cf-agent", sock:sock);

foreach binFile(paths) {

  binFile = chomp(binFile);
  if(!binFile)
    continue;

  cfVer = ssh_get_bin_version(full_prog_name:binFile, sock:sock, version_argv:"--version", ver_pattern:"CFEngine.?([C|c]ore).?([0-9.]+)");
  if(cfVer[2]) {
    set_kb_item(name:"cfengine/running", value:TRUE);
    set_kb_item(name:"cfengine/version", value:cfVer[2]);

    cpe = build_cpe(value:cfVer[2], exp:"^([0-9.]+)", base:"cpe:/a:gnu:cfengine:");
    if(!cpe)
      cpe = "cpe:/a:gnu:cfengine";

    register_product(cpe:cpe, location:binFile, port:0, service:"ssh-login");

    log_message(data:build_detection_report(app:"CFEngine",
                                            version:cfVer[2],
                                            install:binFile,
                                            cpe:cpe,
                                            concluded:cfVer[2]),
                                            port:0);
  }
}

ssh_close_connection();

exit(0);