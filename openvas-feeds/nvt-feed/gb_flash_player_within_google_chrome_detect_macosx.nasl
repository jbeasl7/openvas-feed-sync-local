# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810614");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-03-14 15:08:22 +0530 (Tue, 14 Mar 2017)");
  script_name("Adobe Flash Player Within Google Chrome Detection (Mac OS X SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");

  script_xref(name:"URL", value:"https://helpx.adobe.com/flash-player/kb/flash-player-google-chrome.html");

  script_tag(name:"summary", value:"SSH login-based detection of Adobe Flash Player within Google Chrome.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

flashIns = ssh_cmd(socket:sock, cmd:"ls ~/Library/Application\ Support/Google/Chrome/PepperFlash");

##A list of directories will be output with flash version as directory names
versions = str_replace(find:'\n', replace:" ", string:flashIns);
versionList = split(versions, sep:' ', keep:FALSE);

##NOTE:: When New Flash Plugin is updated on installed
##a new directory is created. Always there are directories
##of old and latest Flash plugin here. Checking for
##latest version directory only
##Lets figure out largest version present
maxVer = versionList[1];
foreach version(versionList) {
  if(version =~ "^[0-9]+" && maxVer < version) {
    maxVer = version;
  } else {
    continue;
  }
}

flashVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read ~/Library/Application\ Support/Google/Chrome/PepperFlash/" + maxVer + "/PepperFlashPlayer.plugin/Contents/Info.plist CFBundleVersion"));
if(!flashVer || "does not exist" >< flashVer)
  exit(0);

set_kb_item(name:"adobe/flash_player/detected", value:TRUE);
set_kb_item(name:"AdobeFlashPlayer/Chrome/MacOSX/Ver", value:flashVer);

cpe = build_cpe(value:flashVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:flash_player_chrome:");
if(!cpe)
  cpe = "cpe:/a:adobe:flash_player_chrome";

register_product(cpe:cpe, location:"/Applications/", port:0, service:"ssh-login");
log_message(data:build_detection_report(app:"Adobe Flash Player within Google Chrome",
                                        version:flashVer,
                                        install:"/Applications/",
                                        cpe:cpe,
                                        concluded:flashVer));
exit(0);
