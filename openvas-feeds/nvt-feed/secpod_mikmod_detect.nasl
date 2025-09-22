# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900442");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-01-29 15:16:47 +0100 (Thu, 29 Jan 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("MikMod Module Player Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"The script detects the version of MikMod Module Player.");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "MikMod Module Player Version Detection (Linux)";

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

mikmodPath = ssh_find_file(file_name:"/mikmod$", useregex:TRUE, sock:sock);
foreach binary_mikmodName (mikmodPath)
{
  binary_name = chomp(binary_mikmodName);
  if(!binary_name)
    continue;

  mikmodCmd = ssh_get_bin_version(full_prog_name:binary_name, version_argv:"--version", ver_pattern:"MikMod ([0-9]\.[0-9.]+)", sock:sock);
  if(mikmodCmd[1] != NULL)
  {
    set_kb_item(name:"MikMod/Linux/Ver", value:mikmodCmd[1]);
    log_message(data:"MikMod Module Player version " + mikmodCmd[1] + " running at location " + binary_name + " was detected on the host");
    ssh_close_connection();

    cpe = build_cpe(value:mikmodCmd[1], exp:"^([0-9.]+)", base:"cpe:/a:igno_saitz:libmikmod:");
    if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

    exit(0);
  }
}
ssh_close_connection();
