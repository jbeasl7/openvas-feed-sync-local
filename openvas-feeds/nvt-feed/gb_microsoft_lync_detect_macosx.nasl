# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810818");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2017-03-20 12:36:51 +0530 (Mon, 20 Mar 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Lync Detection - Mac OS X");

  script_tag(name:"summary", value:"Detects the installed version of
  Microsoft Lync.

  The script logs in via ssh, searches for folder 'Microsoft Lync.app' and
  queries the related 'info.plist' file for string 'CFBundleShortVersionString'
  via command line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

lyncVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
           "Microsoft\ Lync.app" + "/Contents/Info CFBundleShortVersionString"));

if(isnull(lyncVer) || "does not exist" >< lyncVer){
  exit(0);
}

buildVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
           "Microsoft\ Lync.app" + "/Contents/Info MicrosoftBuildNumber"));

close(sock);


if(buildVer)
{
  lyncVer = lyncVer + "." + buildVer;

  set_kb_item(name: "Microsoft/Lync/MacOSX/Version", value:lyncVer);

  cpe = build_cpe(value:lyncVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:lync:");
  if(isnull(cpe))
    cpe='cpe:/a:microsoft:lync';

  path = '/Applications/Microsoft Lync.app/';

  register_product(cpe:cpe, location:path);

  log_message(data: build_detection_report(app:"Microsoft Lync",
                                           version:lyncVer,
                                           install:path,
                                           cpe:cpe,
                                           concluded:lyncVer));
}
exit(0);
