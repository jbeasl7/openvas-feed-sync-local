# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902633");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-11-17 17:38:48 +0530 (Thu, 17 Nov 2011)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("VMware Fusion Detection (Mac OS X SSH Login)");

  script_tag(name:"summary", value:"Detects the installed version of VMware Fusion.

The script logs in via ssh, searches for folder 'VMware Fusion.app' and
queries the related 'info.plist' file for string 'CFBundleShortVersionString'
via command line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
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

vmfusionVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                "VMware\ Fusion.app/Contents/Info CFBundleShortVersionString"));
close(sock);

if(isnull(vmfusionVer) || "does not exist" >< vmfusionVer){
  exit(0);
}

set_kb_item(name: "VMware/Fusion/MacOSX/Version", value:vmfusionVer);

cpe = build_cpe(value:vmfusionVer, exp:"^([0-9.]+)", base:"cpe:/a:vmware:fusion:");
if(isnull(cpe))
  cpe='cpe:/a:vmware:fusion';

register_product(cpe:cpe, location:"/Applications/VMware Fusion.app");

log_message(data: build_detection_report(app: "VMware Fusion",
                                         version: vmfusionVer,
                                         install: "/Applications/VMware Fusion.app",
                                         cpe: cpe,
                                         concluded: vmfusionVer));
