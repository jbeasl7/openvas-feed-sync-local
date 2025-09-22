# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800467");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-02-17 08:26:50 +0100 (Wed, 17 Feb 2010)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("FFmpeg Detection (Linux/Unix SSH Login)");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");

  script_copyright("Copyright (C) 2010 Greenbone AG");

  script_family("Product detection");

  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detects the installed version of FFmpeg.");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

paths = ssh_find_bin(prog_name:"ffmpeg", sock:sock);
foreach ffmpegbin (paths)
{

  ffmpegbin = chomp(ffmpegbin);
  if(!ffmpegbin)
    continue;

  ffmpegVer = ssh_get_bin_version(full_prog_name:ffmpegbin, sock:sock, version_argv:"--version", ver_pattern:"version ([0-9.]+)");
  if(ffmpegVer[1] != NULL)
  {
    set_kb_item(name:"FFmpeg/Linux/Ver", value:ffmpegVer[1]);
    ssh_close_connection();

    register_and_report_cpe(app:"FFmpeg", ver:ffmpegVer[1], base:"cpe:/a:ffmpeg:ffmpeg:", expr:"^([0-9.]+)", insloc:ffmpegbin);

    exit(0);
  }
}

ssh_close_connection();
