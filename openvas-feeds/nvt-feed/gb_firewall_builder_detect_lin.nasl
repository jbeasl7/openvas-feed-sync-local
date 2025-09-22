# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800995");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Firewall Builder Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detects the installed version of Firewall Builder.");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Firewall Builder Version Detection (Linux)";

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

paths = ssh_find_bin(prog_name:"fwbuilder", sock:sock);
foreach fwbuildbin (paths)
{

  fwbuildbin = chomp(fwbuildbin);
  if(!fwbuildbin)
    continue;

  fwbuildVer = ssh_get_bin_version(full_prog_name:fwbuildbin, sock:sock, version_argv:"-v", ver_pattern:"([0-9.]+)");
  if(fwbuildVer[1] != NULL)
  {
    set_kb_item(name:"FirewallBuilder/Linux/Ver", value:fwbuildVer[1]);
    log_message(data:"Firewall Builder version " + fwbuildVer[1] + " running at location " + fwbuildbin + " was detected on the host");

    cpe = build_cpe(value:fwbuildVer[1], exp:"^([0-9.]+)", base:"cpe:/a:fwbuilder:firewall_builder:");
    if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);
  }
}
ssh_close_connection();
