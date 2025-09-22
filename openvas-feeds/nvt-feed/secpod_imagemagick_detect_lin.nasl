# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900563");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-06-02 08:16:42 +0200 (Tue, 02 Jun 2009)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("ImageMagick Detection (Linux/Unix SSH Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  ImageMagick on Linux.

  The script logs in via ssh, searches for executable 'identify' and
  queries the found executables via command line option '-version'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

getPath = ssh_find_bin(prog_name:"identify", sock:sock);
foreach executableFile (getPath)
{
  executableFile = chomp(executableFile);
  if(!executableFile)
    continue;

  imageVer = ssh_get_bin_version(full_prog_name:executableFile, version_argv:"-version", ver_pattern:"ImageMagick ([0-9.]+\-?[0-9]{0,3})", sock:sock);

  if(imageVer[1] != NULL)
  {
    imageVer[1] = ereg_replace(pattern:"-", string:imageVer[1], replace: ".");
    set_kb_item(name:"ImageMagick/Lin/Ver", value:imageVer[1]);
    ssh_close_connection();

    register_and_report_cpe( app: "ImageMagick",
                             ver: imageVer[1],
                             concluded: imageVer[0],
                             base: "cpe:/a:imagemagick:imagemagick:",
                             expr: "^([0-9.]+)",
                             insloc: executableFile );

    exit(0);
  }
}

ssh_close_connection();
