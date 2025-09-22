# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902106");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-02-02 07:26:26 +0100 (Tue, 02 Feb 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("RealPlayer Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detects the installed version of RealPlayer.");
  exit(0);
}

include("ssh_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

rpbin = ssh_find_bin(prog_name:"realplay", sock:sock);
if(isnull(rpbin))
  exit(0);

foreach dir(make_list("/opt/real/RealPlayer", "/usr/local/RealPlayer"))
{
  paths = ssh_find_file(file_name: dir + "/README$", useregex:TRUE, sock:sock);
  foreach binName (paths)
  {

    binName = chomp(binName);
    if(!binName)
      continue;

    rpVer = ssh_get_bin_version(full_prog_name:"cat", version_argv:binName, ver_pattern:"RealPlayer ([0-9.]+)", sock:sock);
    if(rpVer[1] != NULL)
    {
      set_kb_item(name:"RealPlayer/Linux/Ver", value:rpVer[1]);
      log_message(data:"RealPlayer version " + rpVer[1] + " running at location " + binName + " was detected on the host");
      exit(0);
    }
  }
}
ssh_close_connection();
