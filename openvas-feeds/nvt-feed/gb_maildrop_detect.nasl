# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800291");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-02-08 10:53:20 +0100 (Mon, 08 Feb 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Maildrop Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script finds the installed Maildrop version.");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Maildrop Version Detection";

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

mailName = ssh_find_bin(prog_name:"maildrop", sock:sock);
foreach binary_mailName (mailName)
{

  binary_mailName = chomp(binary_mailName);
  if(!binary_mailName)
    continue;

  mailVer = ssh_get_bin_version(full_prog_name:binary_mailName, version_argv:"-version", ver_pattern:"maildrop ([0-9.]+)", sock:sock);
  if(mailVer[1])
  {
    set_kb_item(name:"Maildrop/Linux/Ver", value:mailVer[1]);
    log_message(data:"Maildrop version " + mailVer[1] + " running at location " + binary_mailName + " was detected on the host");

    cpe = build_cpe(value:mailVer[1], exp:"^([0-9.]+)", base:"cpe:/a:maildrop:maildrop:");
    if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);
  }
}
ssh_close_connection();
