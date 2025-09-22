# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801916");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-04-13 15:50:09 +0200 (Wed, 13 Apr 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("VMware Open Virtual Machine Tools Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of VMware Open Virtual Machine
  Tools.");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

paths = ssh_find_bin(prog_name:"vmtoolsd", sock:sock);
foreach bin(paths) {

  bin = chomp(bin);
  if(!bin)
    continue;

  lftVer = ssh_get_bin_version(full_prog_name:bin, sock:sock, version_argv:"-v", ver_pattern:"version ([0-9.]+)");
  if(lftVer[1]) {
    buildVer = ssh_get_bin_version(full_prog_name:bin, sock:sock, version_argv:"-v", ver_pattern:"build-([0-9.]+)");
    if(buildVer[1]) {
      version = lftVer[1] + " build " + buildVer[1];
    }
    else {
      version = lftVer[1];
    }

    set_kb_item(name:"VMware/OVM/Tools/Ver", value:version);

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:vmware:open-vm-tools:");
    if(!cpe)
      cpe = "cpe:/a:vmware:open-vm-tools";

    register_product(cpe:cpe, location:bin, port:0, service:"ssh-login");
    log_message(data:build_detection_report(app:"VMware Open Virtual Machine Tools",
                                            version:version,
                                            install:bin,
                                            cpe:cpe,
                                            concluded:lftVer[0]));

  }
}

ssh_close_connection();
exit(0);
