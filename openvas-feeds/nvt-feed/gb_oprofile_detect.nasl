# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802109");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-06-20 15:22:27 +0200 (Mon, 20 Jun 2011)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("OProfile Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Checks whether OProfile is present on
  the target system and if so, tries to figure out the installed version.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

binaries = ssh_find_bin(prog_name:"oprofiled", sock:sock);
foreach binary(binaries) {

  binary = chomp(binary);
  if(!binary)
    continue;

  # nb: The -v parameter is including the full path to the binary, this is not a functionality of our get_bin_version() function...
  # /path/to/oprofiled: oprofile 0.9.9 compiled on Jun 25 2018 00:00:00
  vers = ssh_get_bin_version(full_prog_name:binary, version_argv:"-v", ver_pattern:"oprofile ([0-9.]{2,})", sock:sock);
  if(vers[1]) {

    set_kb_item(name:"oprofile/detected", value:TRUE);

    cpe = build_cpe(value:vers[1], exp:"^([0-9.]+)", base:"cpe:/a:maynard_johnson:oprofile:");
    if(!cpe)
      cpe = "cpe:/a:maynard_johnson:oprofile";

    register_product(cpe:cpe, port:0, location:binary, service:"ssh-login");

    report = build_detection_report(app:"OProfile", version:vers[1], install:binary, cpe:cpe, concluded:vers[max_index(vers)-1]);
    log_message(port:0, data:report);
  }
}

ssh_close_connection();
exit(0);
