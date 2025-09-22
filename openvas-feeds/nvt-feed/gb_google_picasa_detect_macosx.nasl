# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806629");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-11-26 13:02:06 +0530 (Thu, 26 Nov 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Google Picasa Detection (Mac OS X SSH Login)");

  script_tag(name:"summary", value:"Detection of installed version
  of Google Picasa.

  The script logs in via ssh, searches for folder 'Picasa.app' and queries
  the related 'info.plist' file for string 'CFBundleVersion' via command
  line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

picVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
      "/Picasa.app/Contents/Info CFBundleVersion"));

if(isnull(picVer) || "does not exist" >< picVer){
   exit(0);
}

set_kb_item(name: "picVer/MacOSX/Version", value:picVer);

cpe = build_cpe(value:picVer, exp:"^([0-9.]+)", base:"cpe:/a:google:picasa:");
if(isnull(cpe)){
  cpe = 'cpe:/a:google:picasa:';
}

path = '/Applications/Picasa.app/';

register_product(cpe:cpe, location:path);

log_message(data: build_detection_report(app: "Google Picasa", version: picVer,
                                         install: path,
                                         cpe: cpe,
                                         concluded: picVer));
