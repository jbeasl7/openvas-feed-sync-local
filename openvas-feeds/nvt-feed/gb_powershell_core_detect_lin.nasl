# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812746");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-01-31 10:53:40 +0530 (Wed, 31 Jan 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("PowerShell Detection (Linux/Unix SSH Login)");

  script_tag(name:"summary", value:"SSH login-based detection of PowerShell.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

list = make_list("pwsh-preview", "pwsh");
foreach pgm (list) {
  paths = ssh_find_bin(prog_name:pgm, sock:sock);
  foreach bin(paths) {

    bin = chomp(bin);
    if(!bin)
      continue;

    psVer = ssh_get_bin_version(full_prog_name:bin, sock:sock, version_argv:"-v", ver_pattern:"PowerShell v?([0-9a-z.-]+)");

    if(psVer[1]) {

      ##For preview versions
      psVer = ereg_replace(pattern:"-preview", string:psVer[1], replace:"");

      set_kb_item(name:"PowerShell/Linux/Ver", value:psVer);

      cpe = build_cpe(value:psVer, exp:"^([0-9rc.-]+)", base:"cpe:/a:microsoft:powershell:");
      if(!cpe)
        cpe = "cpe:/a:microsoft:powershell";

      register_product(cpe:cpe, location:bin, port:0, service:"ssh-login");

      log_message(data:build_detection_report(app:"PowerShell",
                                              version:psVer,
                                              install:bin,
                                              cpe:cpe,
                                              concluded:psVer));
    }
  }
}

ssh_close_connection();
exit(0);
