# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812928");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-02-15 15:00:46 +0530 (Thu, 15 Feb 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Adobe Acrobat DC (Classic Track) Detection (Mac OS X SSH Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  Adobe Acrobat DC (Classic Track).

  The script logs in via ssh, searches for folder 'Adobe Acrobat 2015'
  and queries the related 'info.plist' file for string 'CFBundleShortVersionString'
  via command line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");

  script_xref(name:"URL", value:"https://acrobat.adobe.com/us/en/acrobat.html");

  exit(0);
}

include("cpe.inc");
include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

psVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                                       "Adobe\ Acrobat\ 2015/Adobe\ Acrobat.app/Contents/Info CFBundleShortVersionString"));
close(sock);
if(isnull(psVer) || "does not exist" >< psVer){
  exit(0);
}

set_kb_item(name: "Adobe/AcrobatDC/Classic/MacOSX/Version", value:psVer);

cpe = build_cpe(value:psVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:acrobat_dc_classic:");
if(isnull(cpe))
  cpe = 'cpe:/a:adobe:acrobat_dc_classic';

register_product(cpe:cpe, location:'/Applications/Adobe Acrobat 2015');

log_message(data: build_detection_report(app: "Adobe Acrobat DC Classic",
                                         version: psVer,
                                         install: "/Applications/Adobe Acrobat 2015",
                                         cpe: cpe,
                                         concluded: psVer));
exit(0);
