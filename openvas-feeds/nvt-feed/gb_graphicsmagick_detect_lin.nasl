# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800516");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-02-18 15:32:11 +0100 (Wed, 18 Feb 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("GraphicsMagick Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detects the installed version of GraphicsMagick.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

CPE = "cpe:/a:graphicsmagick:graphicsmagick:";

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

gmName = ssh_find_file(file_name:"/gm$", useregex:TRUE, sock:sock);
if(!gmName) {
  ssh_close_connection();
  exit(0);
}

foreach binary_gmName(gmName) {

  binary_name = chomp(binary_gmName);
  if(!binary_name)
    continue;

  gmVer = ssh_get_bin_version(full_prog_name:binary_name, version_argv:"-version", ver_pattern:"GraphicsMagick ([0-9.]+)", sock:sock);
  if(isnull(gmVer[1]))
    continue;

  set_kb_item(name:"GraphicsMagick/Linux/Ver", value:gmVer[0]);
  ssh_close_connection();

  register_and_report_cpe(app:"GraphicsMagick",
                          ver:gmVer[1],
                          concluded:gmVer[0],
                          base:CPE,
                          expr:"([0-9.]+)",
                          insloc:binary_gmName,
                          regService:"ssh");

  exit(0);
}

ssh_close_connection();

exit(0);
