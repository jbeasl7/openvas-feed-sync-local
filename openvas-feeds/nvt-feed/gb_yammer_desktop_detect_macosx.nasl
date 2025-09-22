# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814325");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-11-22 11:38:37 +0530 (Thu, 22 Nov 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Yammer Desktop Detection (Mac OS X SSH Login)");

  script_tag(name:"summary", value:"Detects the installed version of Yammer Desktop
  on Mac OS X.

  The script logs in via ssh, searches for folder 'Yammer.app' and
  queries the related 'info.plist' file for string 'CFBundleShortVersionString'
  via command line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
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

yamVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                      "Yammer.app/Contents/Info CFBundleShortVersionString"));

close(sock);
if(isnull(yamVer) || "does not exist" >< yamVer){
  exit(0);
}

set_kb_item(name:"Microsoft/Yammer/Macosx/Ver", value:yamVer);
cpe = build_cpe(value:yamVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:yammer:");
if(isnull(cpe)){
  cpe = "cpe:/a:microsoft:yammer";
}

register_product(cpe: cpe, location:'/Applications/Yammer.app', service:"ssh-login", port:0);

report =  build_detection_report(app: "Microsoft Yammer",
                                 version: yamVer,
                                 install: "/Applications/Yammer.app",
                                 cpe: cpe,
                                 concluded: yamVer);
if(report){
  log_message( port:0, data:report );
}

exit(0);
