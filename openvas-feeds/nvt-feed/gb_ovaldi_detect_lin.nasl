# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803368");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-04-04 17:10:57 +0530 (Thu, 04 Apr 2013)");
  script_name("Ovaldi Detection (Linux/Unix SSH Login)");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Ovaldi.");

  exit(0);
}

include("cpe.inc");
include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

path = ssh_find_bin(prog_name:"ovaldi",sock:sock);
foreach binName(path) {

  binName = chomp(binName);
  if(!binName)
    continue;

  ovaldiVer = ssh_get_bin_version(full_prog_name:binName, version_argv:"-V", ver_pattern:"Version: ([0-9.]+).?(Build: ([0-9]+))?", sock:sock);

  if(!isnull(ovaldiVer[1]) && !isnull(ovaldiVer[3])) {
    ver = ovaldiVer[1] + "." + ovaldiVer[3];
  }
  else if(!isnull(ovaldiVer [1]) && isnull(ovaldiVer[3])) {
    ver = ovaldiVer[1];
  }

  if(ver) {

    set_kb_item(name:"Ovaldi/Linux/Version", value:ver);

    cpe = build_cpe(value:ver, exp:"^([0-9.]+)", base:"cpe:/a:mitre:ovaldi:");
    if(!cpe)
      cpe = "cpe:/a:mitre:ovaldi";

    register_product(cpe:cpe, location:binName, port:0, service:"ssh-login");
    log_message(data:build_detection_report(app:"Ovaldi",
                                            version:ver,
                                            install:binName,
                                            cpe:cpe,
                                            concluded:ovaldiVer[0]));
  }
}

ssh_close_connection();
exit(0);
