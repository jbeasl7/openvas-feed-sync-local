# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809872");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-01-20 15:36:08 +0530 (Fri, 20 Jan 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Pidgin Detection (Mac OS X SSH Login)");
  script_tag(name:"summary", value:"Detects the installed version of
  Pidgin on Mac OS X.

  The script logs in via ssh, searches for folder 'pidgin' and queries the
  version from 'Changelog' file.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}

include("cpe.inc");
include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

pidgin_file = ssh_find_file(file_name:"/usr/local/Cellar/pidgin/ChangeLog$", useregex:TRUE, sock:sock);

foreach path (pidgin_file)
{
  path = chomp(path);
  if(!path)
    continue;

  pidgin = ssh_get_bin_version(full_prog_name:"cat", version_argv:path, ver_pattern:"pidgin", sock:sock);

  if(pidgin[0] != NULL)
  {
    pidgin_Ver = ssh_get_bin_version(full_prog_name:"cat", version_argv:path, ver_pattern:"version ([0-9.]+)", sock:sock);

    if(pidgin_Ver[1])
    {
      set_kb_item(name: "Pidgin/MacOSX/Version", value:pidgin_Ver[1]);

      cpe = build_cpe(value:pidgin_Ver[1], exp:"^([0-9.]+)", base:"cpe:/a:pidgin:pidgin:");
      if(isnull(cpe))
        cpe = "cpe:/a:pidgin:pidgin";

      register_product(cpe:cpe, location:path);

      log_message(data: build_detection_report(app: "Pidgin",
                                               version: pidgin_Ver[1],
                                               install: path,
                                               cpe: cpe,
                                               concluded: pidgin_Ver[1]));
      exit(0);
    }
  }
}

close(sock);
exit(0);
