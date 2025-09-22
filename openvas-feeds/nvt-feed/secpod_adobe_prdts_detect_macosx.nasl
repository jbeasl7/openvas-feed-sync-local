# Copyright (C) 2011 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902711");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2011-08-10 13:49:51 +0200 (Wed, 10 Aug 2011)");
  script_name("Adobe Products Detection (Mac OS X SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");

  script_tag(name:"summary", value:"SSH login-based detection of various Adobe products.");

  script_tag(name:"insight", value:"The following Adobe products are detected:

  - Adobe Flash Player

  - Adobe Shockwave Player

  - Adobe Air

  - Adobe Reader

  - Adobe Acrobat");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("cpe.inc");
include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

if(!get_kb_item("ssh/login/osx_name")) {
  close(sock);
  exit(0);
}

buffer = get_kb_item("ssh/login/osx_pkgs");
if(buffer) {
  if("com.adobe.pkg.FlashPlayer" >< buffer) {
    flashVer = eregmatch(pattern:"FlashPlayer[^\n]([0-9.]+)", string:buffer);
  } else {
    version = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Library/Internet\ Plug-Ins/Flash\ Player.plugin/Contents/Info.plist"));
    if(version && "does not exist" >!< version)
      flashVer = eregmatch(pattern:'CFBundleVersion = "([0-9.]+)"', string:version);
  }

  if(!isnull(flashVer[1])) {
    set_kb_item(name:"adobe/flash_player/detected", value:TRUE);
    set_kb_item(name:"Adobe/Flash/Player/MacOSX/Version", value:flashVer[1]);
    set_kb_item(name:"Adobe/Air_or_Flash_or_Reader/MacOSX/Installed", value:TRUE);
    register_and_report_cpe(app:"Adobe Flash Player", ver:flashVer[1], base:"cpe:/a:adobe:flash_player:", expr:"^([0-9.]+)", insloc:"/Applications/Install Adobe Flash Player.app", regPort:0, regService:"ssh-login");
  }
}

if("com.adobe.shockwave" >< buffer) {
  version = eregmatch(pattern:"shockwave[^\n]([0-9.]+)", string:buffer);
  if(version[1]) {
    set_kb_item(name:"Adobe/Shockwave/Player/MacOSX/Version", value:version[1]);
    set_kb_item(name:"Adobe/Air_or_Flash_or_Reader/MacOSX/Installed", value:TRUE);
    register_and_report_cpe(app:"Adobe Shockwave Player", ver:version[1], base:"cpe:/a:adobe:shockwave_player:", expr:"^([0-9.]+)", insloc:"/Applications", regPort:0, regService:"ssh-login");
  }
}

airVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/Adobe\ AIR\ Installer.app/Contents/Info CFBundleShortVersionString"));
if(!isnull(airVer) && "does not exist" >< airVer)
  airVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Library/Frameworks/Adobe\ AIR.framework/Versions/Current/Resources/Info.plist " + "CFBundleVersion"));

if(!isnull(airVer) && "does not exist" >!< airVer) {
  set_kb_item(name:"Adobe/Air/MacOSX/Version", value:airVer);
  set_kb_item(name:"Adobe/Air_or_Flash_or_Reader/MacOSX/Installed", value:TRUE);
  register_and_report_cpe(app:"Adobe Air", ver:airVer, base:"cpe:/a:adobe:adobe_air:", expr:"^([0-9.]+)", insloc:"/Applications/Adobe AIR Installer.app", regPort:0, regService:"ssh-login");
}

readerVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/Adobe\ Reader.app/Contents/Info CFBundleShortVersionString"));

app = "Adobe Reader";
if(isnull(readerVer) || "does not exist" >< readerVer) {
  readerVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/Adobe\ Acrobat\ Reader\ 2017.app/Contents/Info CFBundleShortVersionString"));
  app = "Adobe Reader 2017";
}

if(!isnull(readerVer) && "does not exist" >!< readerVer) {
  set_kb_item(name:"Adobe/Reader/MacOSX/Version", value:readerVer);
  set_kb_item(name:"Adobe/Air_or_Flash_or_Reader/MacOSX/Installed", value:TRUE);
  register_and_report_cpe(app:app, ver:readerVer, base:"cpe:/a:adobe:acrobat_reader:", expr:"^([0-9.]+)", insloc:"/Applications/Adobe Reader.app", regPort:0, regService:"ssh-login");
}

foreach ver(make_list("2017", "XI", "X", "10", "9", "8")) {
  if(ver == "2017")
    acrobatVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/Adobe\ Acrobat\ 2017/Adobe\ Acrobat.app/Contents/Info CFBundleShortVersionString"));
  else
    acrobatVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/Adobe\ Acrobat\ " + ver + "\ Pro/Adobe\ Acrobat\ Pro.app/Contents/Info CFBundleShortVersionString"));

  if(acrobatVer && "does not exist" >!< acrobatVer)
    break;

}

if(!isnull(acrobatVer) && "does not exist" >!< acrobatVer) {
  set_kb_item(name:"Adobe/Acrobat/MacOSX/Version", value:acrobatVer);
  set_kb_item(name:"Adobe/Air_or_Flash_or_Reader/MacOSX/Installed", value:TRUE);
  register_and_report_cpe(app:"Adobe Acrobat " + ver, ver:acrobatVer, base:"cpe:/a:adobe:acrobat:", expr:"^([0-9.]+)", insloc:"/Applications/Adobe Acrobat", regPort:0, regService:"ssh-login");
}

close(sock);
exit(0);
