# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801340");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Aria2 Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script finds the Aria2 installed version.");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Aria2 Version Detection";

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

paths = ssh_find_bin(prog_name:"aria2c", sock:sock);
foreach aria2bin (paths)
{

  aria2bin = chomp(aria2bin);
  if(!aria2bin)
    continue;

  aria2Ver = ssh_get_bin_version(full_prog_name:aria2bin, sock:sock, version_argv:"--v", ver_pattern:"version ([0-9.]+)");
  if(aria2Ver[1] != NULL)
  {
    set_kb_item(name:"Aria2/Ver", value:aria2Ver[1]);
    log_message(data:"Aria2 version " + aria2Ver[1] + " running at location " + aria2bin + " was detected on the host");

    cpe = build_cpe(value:aria2Ver[1], exp:"^([0-9.]+)", base:"cpe:/a:tatsuhiro_tsujikawa:aria2:");
    if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);
  }
}
ssh_close_connection();
