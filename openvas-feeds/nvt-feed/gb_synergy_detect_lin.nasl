# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801874");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Synergy Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Synergy.");

  exit(0);
}

include("cpe.inc");
include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

paths = ssh_find_bin(prog_name:"synergys", sock:sock);
foreach bin(paths) {

  bin = chomp(bin);
  if(!bin)
    continue;

  synVer = ssh_get_bin_version(full_prog_name:bin, sock:sock, version_argv:"--version", ver_pattern:"synergys ([0-9.]+)");

  if(!isnull(synVer[1])) {
    set_kb_item(name:"Synergy/Lin/Ver", value:synVer[1]);

    cpe = build_cpe(value:synVer[1], exp:"^([0-9.]+)", base:"cpe:/a:synergy-foss:synergy:");
    if(!cpe)
      cpe = "cpe:/a:synergy-foss:synergy";

    register_product(cpe:cpe, location:bin, port:0, service:"ssh-login");
    log_message(data:build_detection_report(app:"Synergy",
                                            version:synVer[1],
                                            install:bin,
                                            cpe:cpe,
                                            concluded:synVer[0]));
  }
}

ssh_close_connection();
exit(0);
