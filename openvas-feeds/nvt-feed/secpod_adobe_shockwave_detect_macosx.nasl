# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902619");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)");
  script_name("Adobe Shockwave Player Detection (Mac OS X SSH Login)");

  script_tag(name:"summary", value:"Detects the installed version of Adobe
  Shockwave Player on Mac OS X.

  The script logs in via ssh, and searches for adobe products '.app' folder
  and queries the related 'info.plist' file for string 'CFBundleShortVersionString'
  via command line option 'defaults read'.");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
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

if (!get_kb_item("ssh/login/osx_name"))
{
  close(sock);
  exit(0);
}

shockVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Library/" +
          "Application\ Support/Adobe/Shockwave/DirectorShockwave.bundle/"+
          "Contents/Info CFBundleShortVersionString"));

if(isnull(shockVer) || "does not exist" >< shockVer)
{
  for(i=8; i<=12; i++)
  {
    shockVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Library/" +
               "Application\ Support/Adobe/Shockwave\ "+ i +
               "/DirectorShockwave.bundle/Contents/Info " +
               "CFBundleShortVersionString"));

    if("does not exist" >!< shockVer){
       break;
    }
  }
}

if(isnull(shockVer) || "does not exist" >< shockVer)
{
  for(i=8; i<=12; i++)
  {
    shockVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Library/" +
               "Application\ Support/Macromedia/Shockwave\ "+ i +
               "/Shockwave.bundle/Contents/Info CFBundleShortVersionString"));

    if("does not exist" >!< shockVer){
       break;
    }
  }
}

close(sock);

if(isnull(shockVer) || "does not exist" >< shockVer){
  exit(0);
}

shockVer = ereg_replace(pattern:"r", string:shockVer, replace: ".");

set_kb_item(name: "Adobe/Shockwave/MacOSX/Version", value:shockVer);

cpe = build_cpe(value: shockVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:shockwave_player:");
if(isnull(cpe))
  cpe = "cpe:/a:adobe:shockwave_player";

register_product(cpe: cpe, location: "/Library/");

log_message(data: build_detection_report(app: "Adobe Shockwave Player",
                                         version: shockVer,
                                         install: "/Applications/",
                                         cpe: cpe,
                                         concluded: shockVer));
