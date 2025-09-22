# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813474");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-07-10 11:02:12 +0530 (Tue, 10 Jul 2018)");
  script_name("Node.js Detection (Mac OS X SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detects the installed version of
  Node.js on Mac OS X.

  The script logs in via ssh, and gets the version via command line option
  'node -v'.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

paths = ssh_find_bin(prog_name:"node", sock:sock);
foreach nodebin (paths)
{

  nodebin = chomp(nodebin);
  if(!nodebin)
    continue;

  nodeVer = ssh_get_bin_version(full_prog_name:nodebin, sock:sock, version_argv:"-v", ver_pattern:"v([0-9.]+)");
  if(nodeVer[1])
  {
    set_kb_item(name:"Nodejs/MacOSX/Installed", value:TRUE);
    set_kb_item(name:"Nodejs/MacOSX/Ver", value:nodeVer[1]);

    register_and_report_cpe(app:"Node.js", ver:nodeVer[1], base:"cpe:/a:nodejs:node.js:", expr:"^([0-9.]+)", insloc:nodebin );
    ssh_close_connection();
    exit(0);
  }
}
ssh_close_connection();
exit(0);
