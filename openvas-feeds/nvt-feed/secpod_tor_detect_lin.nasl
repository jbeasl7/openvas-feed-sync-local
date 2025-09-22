# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900418");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-12-31 15:14:17 +0100 (Wed, 31 Dec 2008)");
  script_tag(name:"qod_type", value:"executable_version");

  script_name("Tor Detection (Linux/Unix SSH Login)");
  script_tag(name:"summary", value:"Detects the installed version of Tor.

  The script logs in via ssh, searches for executable 'tor' and
  queries the found executables via command line option '--version'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ssh_func.inc");

tor_sock = ssh_login_or_reuse_connection();
if(!tor_sock)
  exit(0);

torName = ssh_find_file(file_name:"/tor$", useregex:TRUE, sock:tor_sock);

foreach binaryName (torName)
{
  binaryName = chomp(binaryName);
  if(!binaryName)
    continue;

  torVer = ssh_get_bin_version(full_prog_name:binaryName, sock:tor_sock, version_argv:"--version", ver_pattern:"Tor (v|version )([0-9.]+-?([a-z0-9]+)?)");
  if(torVer[2] != NULL)
  {
    set_kb_item(name:"Tor/Linux/Ver", value:torVer[2]);

    cpe = build_cpe(value: torVer[2], exp:"^([0-9.]+-?([a-z0-9]+)?)", base:"cpe:/a:tor:tor:");
    if(isnull(cpe))
      cpe = 'cpe:/a:tor:tor';

    register_product(cpe:cpe, location:binaryName);

    log_message(data:build_detection_report(app: "Tor",
                                             version: torVer[2],
                                             install: binaryName,
                                             cpe: cpe,
                                             concluded: torVer[2]));
  }
}
ssh_close_connection();
