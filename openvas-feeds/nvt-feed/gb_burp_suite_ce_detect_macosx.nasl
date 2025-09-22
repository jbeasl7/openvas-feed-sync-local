# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813610");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-06-19 16:38:09 +0530 (Tue, 19 Jun 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Burp Suite Community Edition Detection (Mac OS X SSH Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  Burp Suite Community Edition on Mac OS X.

  The script logs in via ssh, searches for folder
  'Burp Suite Community Edition Installer.app' and queries the related 'info.plist'
   file for string 'CFBundleShortVersionString' via command line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}

include("cpe.inc");
include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

burpVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                                       "Burp\ Suite\ Community\ Edition\ Installer.app/Contents/Info CFBundleShortVersionString"));

close(sock);

if(isnull(burpVer) || "does not exist" >< burpVer){
  exit(0);
}

set_kb_item(name: "BurpSuite/CE/MacOSX/Version", value:burpVer);

## New cpe created
cpe = build_cpe(value:burpVer, exp:"^([0-9.]+)", base:"cpe:/a:portswigger:burp_suite:");
if(isnull(cpe))
  cpe = 'cpe:/a:portswigger:burp_suite';

register_product(cpe:cpe, location:'/Applications/Burp Suite Community Edition Installer.app');

log_message(data: build_detection_report(app: "Burp Suite Community Edition",
                                         version: burpVer,
                                         install: "/Applications/Burp Suite Community Edition Installer.app",
                                         cpe: cpe,
                                         concluded: burpVer));
exit(0);
