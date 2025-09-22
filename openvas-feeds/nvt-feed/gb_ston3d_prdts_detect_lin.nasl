# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800575");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-06-16 15:11:01 +0200 (Tue, 16 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("StoneTrip Ston3D Standalone Player Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detects the installed version of StoneTrip Ston3D
  Standalone Player.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

sapName = ssh_find_file(file_name:"/S3DEngine_Linux$", useregex:TRUE, sock:sock);
if(!sapName) {
  ssh_close_connection();
  exit(0);
}

garg[0] = "-o";
garg[1] = "-m1";
garg[2] = "-a";
garg[3] = string("Standalone Engine [0-9.]\\+");

foreach binaryName(sapName) {

  binaryName = chomp(binaryName);
  if(!binaryName)
    continue;

  arg = garg[0] + " " + garg[1] + " " + garg[2] + " " + raw_string(0x22) + garg[3] + raw_string(0x22) + " " + binaryName;

  sapVer = ssh_get_bin_version(full_prog_name:"grep", version_argv:arg, sock:sock, ver_pattern:"([0-9.]{3,})");
  if(sapVer[1]) {

    set_kb_item(name:"Ston3D/Standalone/Player/Lin/Ver", value:sapVer[1]);
    register_and_report_cpe(app:"StoneTrip Ston3D Standalone Player", ver:sapVer[1], base:"cpe:/a:stonetrip:s3dplayer_standalone:", expr:"([0-9.]+)", regPort:0, insloc:binaryName, concluded:sapVer[0], regService:"ssh-login");
    break;
  }
}

ssh_close_connection();
exit(0);
