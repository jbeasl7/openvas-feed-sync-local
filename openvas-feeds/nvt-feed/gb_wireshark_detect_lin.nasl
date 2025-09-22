# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800039");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-07-22T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2008-10-24 15:11:55 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Wireshark Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Wireshark on Linux/Unix.");

  script_tag(name:"vuldetect", value:"The script logs in via SSH, searches for executable
  'wireshark' and queries the found executables via command line option '-v'.");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

wiresharkName = ssh_find_file(file_name:"/wireshark$", useregex:TRUE, sock:sock);
foreach executableFile (wiresharkName) {

  executableFile = chomp(executableFile);
  if(!executableFile)
    continue;

  sharkVer = ssh_get_bin_version(full_prog_name:executableFile, version_argv:"-v", ver_pattern:"[Ww]ireshark ([0-9.]+)", sock:sock);
  if(sharkVer) {

    set_kb_item(name:"wireshark/detected", value:TRUE);
    set_kb_item(name:"wireshark/linux/detected", value:TRUE);

    cpe = build_cpe(value:sharkVer[1], exp:"^([0-9.]+)", base:"cpe:/a:wireshark:wireshark:");
    if(!cpe)
      cpe = "cpe:/a:wireshark:wireshark";

    register_product(cpe:cpe, location:executableFile, port:0, service:"ssh-login");

    log_message(port:0, data:'Detected Wireshark version: ' + sharkVer[1] +
        '\nLocation: ' + executableFile +
        '\nCPE: '+ cpe +
        '\n\nConcluded from version identification result:\n' + sharkVer[max_index(sharkVer)-1]);
  }
}

ssh_close_connection();

exit(0);
