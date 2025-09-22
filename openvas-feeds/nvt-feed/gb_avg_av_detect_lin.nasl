# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800394");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-04-17 09:00:01 +0200 (Fri, 17 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("AVG Anti-Virus Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detect the installed version of AVG Anti-Virus.");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ssh_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

avgPaths = ssh_find_file(file_name:"/avgupdate$", useregex:TRUE, sock:sock);
foreach avgBin (avgPaths)
{

  avgBin = chomp(avgBin);
  if(!avgBin)
    continue;

  filter = ssh_get_bin_version(full_prog_name:avgBin, sock:sock, version_argv:"-v", ver_pattern:"version:? ([0-9.]+)\.([0-9]+)[^.]?");

  # The below steps are carried out to append/increment build by one
  # (since it gets build version always reduced by one.
  if(filter[1] != NULL && filter[2] != NULL)
  {
    end = int(filter[2]) + 1;
    avgVer = filter[1] + "." + end;
    if(avgVer != NULL)
    {
      set_kb_item(name:"avg/antivirus/detected", value:TRUE);
      ssh_close_connection();

      register_and_report_cpe( app:"AVG Anti-Virus",
                               ver:avgVer,
                               concluded:filter[0],
                               base:"cpe:/a:avg:anti-virus:",
                               insloc:avgBin,
                               regService:"ssh-login",
                               regPort:0 );

      exit(0);
    }
  }
}
ssh_close_connection();
exit(0);
