# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900626");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-04-24 16:23:28 +0200 (Fri, 24 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("FreeType Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detects the installed version of FreeType.

  The script logs in via SSH, searches for executable 'freetype-config' and
  queries the found executables via command line option '--ftversion'.");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

binFiles = ssh_find_file(file_name:"/freetype-config$", useregex:TRUE, sock:sock);

foreach executableFile (binFiles) {

  executableFile = chomp(executableFile);
  if(!executableFile)
    continue;

  ftVer = ssh_get_bin_version(full_prog_name:executableFile, sock:sock, version_argv:"--ftversion", ver_pattern:"[0-9.]{3,}");
  if(ftVer[0] != NULL)
  {
    set_kb_item(name:"FreeType/Linux/Ver", value:ftVer[0]);
    register_and_report_cpe( app:"FreeType",
                             ver:ftVer[1],
                             concluded: ftVer[0],
                             base:"cpe:/a:freetype:freetype:",
                             expr:"^([0-9.]+)",
                             insloc:executableFile,
                             regService:"ssh-login" );
  }
}

ssh_close_connection();
