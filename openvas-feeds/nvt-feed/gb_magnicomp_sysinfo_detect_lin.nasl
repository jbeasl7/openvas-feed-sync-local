# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814303");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-10-04 12:30:19 +0530 (Thu, 04 Oct 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("MagniComp SysInfo Detection (Linux/Unix SSH Login)");

  script_tag(name:"summary", value:"This script finds the installed version of
  MagniComp SysInfo on Linux.

  The script logs in via ssh, searches for binary file 'mcsysinfo' and queries
  the file for version");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_xref(name:"URL", value:"https://www.magnicomp.com");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  exit(0);
}

include("cpe.inc");
include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

sysinfoName = ssh_find_bin(prog_name:"mcsysinfo", sock:sock);
foreach executableFile (sysinfoName)
{
  executableFile = chomp(executableFile);
  if(!executableFile)
    continue;

  sysinfoVer = ssh_get_bin_version(full_prog_name:executableFile, version_argv:"-V", ver_pattern:"SysInfo Version ([0-9A-Z. )(]+)", sock:sock);
  if(sysinfoVer)
  {
    version = ereg_replace(pattern:"[()]", string:sysinfoVer[1], replace:"");
    set_kb_item(name:"Sysinfo/Linux/Ver", value:version);

    cpe = register_and_report_cpe(app:"MagniComp SysInfo", ver:version, base:"cpe:/a:magnicomp:sysinfo:",
                                  expr:"^([0-9A-Z. ]+)",insloc:executableFile);
    exit(0);
  }
}

ssh_close_connection();
exit(0);
