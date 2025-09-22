# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802762");
  script_version("2024-07-22T05:05:40+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2012-04-24 14:25:07 +0530 (Tue, 24 Apr 2012)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Wireshark Detection (Mac OS X SSH Login)");

  script_tag(name:"summary", value:"SSH login-based detection of Wireshark on Mac OS X.");

  script_tag(name:"vuldetect", value:"The script logs in via SSH, searches for folder
  'Wireshark.app' and queries the related 'info.plist' file for string 'CFBundleShortVersionString'
  via command line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

if (!get_kb_item("ssh/login/osx_name")) {
  close(sock);
  exit(0);
}

sharkVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/Wireshark.app/Contents/Info CFBundleShortVersionString"));

close(sock);

if(!sharkVer || "does not exist" >< sharkVer)
  exit(0);

set_kb_item(name:"wireshark/detected", value:TRUE);
set_kb_item(name:"wireshark/macosx/detected", value:TRUE);

cpe = build_cpe(value:sharkVer, exp:"^([0-9.]+)", base:"cpe:/a:wireshark:wireshark:");
if(!cpe)
  cpe = "cpe:/a:wireshark:wireshark";

register_product(cpe:cpe, location:"/Applications/Wireshark.app", port:0, service:"ssh-login");

log_message(data:build_detection_report(app:"Wireshark",
                                        version:sharkVer,
                                        install:"/Applications/Wireshark.app",
                                        cpe:cpe,
                                        concluded:sharkVer),
            port:0);

exit(0);
