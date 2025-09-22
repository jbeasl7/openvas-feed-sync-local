# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902701");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("LibreOffice Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script finds the installed LibreOffice
  version.");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

officeName = ssh_find_bin(prog_name:"libreoffice", sock:sock);
foreach binary_officeName (officeName)
{

  binary_officeName = chomp(binary_officeName);
  if(!binary_officeName)
    continue;

  officeVer = ssh_get_bin_version(full_prog_name:binary_officeName, version_argv:"-help", ver_pattern:"LibreOffice ([0-9.]+)", sock:sock);
  if(officeVer[1])
  {
    if(officeVer[2] != NULL)
    {
      buildVer = eregmatch(pattern:"Build.?([0-9.]+)", string:officeVer[2]);
      if(buildVer[1] != NULL)
      {
        tmp_version = officeVer[1] + "." + buildVer[1];
        set_kb_item(name:"LibreOffice/Linux/Ver", value:tmp_version);
        register_and_report_cpe(app:"LibreOffice", ver:tmp_version, base:"cpe:/a:libreoffice:libreoffice:", expr:"^([0-9.]+)", insloc:binary_officeName);
      }
    }
    else
    {
      set_kb_item(name:"LibreOffice/Linux/Ver", value:officeVer[1]);
      register_and_report_cpe(app:"LibreOffice", ver:officeVer[1], base:"cpe:/a:libreoffice:libreoffice:", expr:"^([0-9.]+)", insloc:binary_officeName);
    }
  }
}
close(sock);
ssh_close_connection();
