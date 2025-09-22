# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800300");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Bournal Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script finds the Bournal installed version.");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Bournal Version Detection";

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

bourName = ssh_find_bin(prog_name:"bournal", sock:sock);
foreach binary_bourName (bourName)
{

  binary_bourName = chomp(binary_bourName);
  if(!binary_bourName)
    continue;

  bourVer = ssh_get_bin_version(full_prog_name:binary_bourName, version_argv:"-v", ver_pattern:"Bournal ([0-9.]+)", sock:sock);
  if(!isnull(bourVer[1]))
  {
    set_kb_item(name:"Bournal/Ver", value:bourVer[1]);
    log_message(data:"Bournal version " + bourVer[1] + " running at location " + binary_bourName + " was detected on the host");

    cpe = build_cpe(value:bourVer[1], exp:"^([0-9.]+)", base:"cpe:/a:becauseinter:bournal:");
    if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);
  }
}
ssh_close_connection();
