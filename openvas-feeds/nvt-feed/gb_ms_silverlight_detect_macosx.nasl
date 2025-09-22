# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802854");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-05-14 14:56:10 +0530 (Mon, 14 May 2012)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Silverlight Detection (Mac OS X SSH Login)");

  script_tag(name:"summary", value:"Detects the installed version of Microsoft Silverlight on Mac OS X.

The script logs in via ssh, and searches for Microsoft Silverlight
'Silverlight.plugin' folder and queries the related 'Info.plist' file
for string 'CFBundleShortVersionString' via command line option
'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_family("Product detection");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

slightVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Library/Internet\ Plug-Ins/"+
                          "Silverlight.plugin/Contents/Info CFBundleShortVersionString"));
close(sock);

if(isnull(slightVer) || "does not exist" >< slightVer){
  exit(0);
}

set_kb_item(name: "MS/Silverlight/MacOSX/Ver", value: slightVer);

cpe = build_cpe(value: slightVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:silverlight:");
if(isnull(cpe))
  cpe='cpe:/a:microsoft:silverlight';

register_product(cpe:cpe, location:'/Library/Internet Plug-Ins/Silverlight.plugin');

log_message(data: build_detection_report(app:"Microsoft Silverlight on Mac OS X",
                                         version: slightVer,
                                         install: '/Library/Internet Plug-Ins/Silverlight.plugin',
                                         cpe: cpe,
                                         concluded: slightVer));
