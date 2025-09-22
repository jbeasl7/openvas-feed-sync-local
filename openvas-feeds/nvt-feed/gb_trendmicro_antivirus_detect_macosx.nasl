# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814360");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-12-05 18:17:59 +0530 (Wed, 05 Dec 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Trend Micro Antivirus Detection (Mac OS X SSH Login)");

  script_tag(name:"summary", value:"Detects the installed version of Trend Micro
  Antivirus on Mac OS X.

  The script logs in via ssh, searches for folder 'PackageSelector.app' and
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

appname = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                      "PackageSelector.app/Contents/Info CFBundleIdentifier"));

if("com.trendmicro.iTIS.PackageSelector">< appname){

  tmVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                        "PackageSelector.app/Contents/Info CFBundleShortVersionString"));
}

close(sock);

if(isnull(tmVer) || "does not exist" >< tmVer){
  exit(0);
}

set_kb_item(name:"TrendMicro/Antivirus/Macosx/Ver", value:tmVer);

#created cpe for this product
cpe = build_cpe(value:tmVer, exp:"^([0-9.]+)", base:"cpe:/a:trend_micro:antivirus:");
if(isnull(cpe))
  cpe = "cpe:/a:trend_micro:antivirus";

register_product(cpe: cpe, location:'/Applications/PackageSelector.app', service:"ssh-login", port:0);

report =  build_detection_report(app: "Trend Micro Antivirus",
                             version: tmVer,
                             install: "/Applications/PackageSelector.app",
                                 cpe: cpe,
                           concluded: tmVer);
if(report){
  log_message( port:0, data:report );
}

exit(0);
