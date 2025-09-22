# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801421");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-08-10 14:39:31 +0200 (Tue, 10 Aug 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("rekonq Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of rekonq.");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

rekonqName = ssh_find_bin(prog_name:"rekonq", sock:sock);
foreach binName(rekonqName) {

  binName = chomp(binName);
  if(!binName)
    continue;

  rekonqVer = ssh_get_bin_version(full_prog_name:binName, version_argv:"-v", ver_pattern:"rekonq: ([0-9.]+)", sock:sock);
  if(rekonqVer[1]) {
    set_kb_item(name:"rekonq/Linux/Ver", value:rekonqVer[1]);

    cpe = build_cpe(value:rekonqVer[1], exp:"^([0-9.]+)", base:"cpe:/a:adjam:rekonq:");
    if(!cpe)
      cpe = "cpe:/a:adjam:rekonq";

    register_product(cpe:cpe, location:binName, port:0, service:"ssh-login");
    log_message(data:build_detection_report(app:"rekonq",
                                            version:rekonqVer[1],
                                            install:binName,
                                            cpe:cpe,
                                            concluded:rekonqVer[0]));
  }
}

ssh_close_connection();
exit(0);
