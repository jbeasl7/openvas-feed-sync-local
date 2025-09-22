# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801121");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-10-23 16:18:41 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("GD Graphics Library Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detects the installed version of GD Graphics Library.");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "GD Graphics Library Version Detection (Linux)";

gd_sock = ssh_login_or_reuse_connection();
if(!gd_sock)
  exit(0);

gdName = ssh_find_bin(prog_name:"gdlib-config", sock:gd_sock);

foreach binName (gdName)
{

  binName = chomp(binName);
  if(!binName)
    continue;

  gdVer = ssh_get_bin_version(full_prog_name:binName, sock:gd_sock, version_argv:"--version", ver_pattern:"([0-9.]+.?(RC[0-9])?)");
  if(!isnull(gdVer[1]))
  {
    set_kb_item(name:"GD-Graphics-Lib/Lin/Ver", value:gdVer[1]);
    log_message(data:"GD Graphics Library version " + gdVer[1] + " was detected on the host");

    cpe = build_cpe(value:gdVer[1], exp:"^([0-9.]+\.[0-9])\.?([a-z0-9]+)?", base:"cpe:/a:libgd:gd_graphics_library:");
    if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);
  }
}
ssh_close_connection();
