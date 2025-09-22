# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800339");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-01-19 13:47:40 +0100 (Mon, 19 Jan 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Gale Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script finds the installed version of Gale.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Gale Version Detection";

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

paths = ssh_find_file(file_name:"/gale-config$", useregex:TRUE, sock:sock);
if(!paths) {
  ssh_close_connection();
  exit(0);
}

foreach galeBin(paths) {

  galeBin = chomp(galeBin);
  if(!galeBin)
    continue;

  galeVer = ssh_get_bin_version(full_prog_name:galeBin, sock:sock, version_argv:"--version", ver_pattern:"[0-9.A-Za-z]{3,}");
  if(!isnull(galeVer[0])) {

    set_kb_item(name:"Gale/Linux/Ver", value:galeVer[0]);
    log_message(data:"Gale version " + galeVer[0] + " was detected on the host");
    ssh_close_connection();

    cpe = build_cpe(value:galeVer[0], exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:gale:gale:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

    exit(0);
  }
}
ssh_close_connection();
