# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810265");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-01-10 12:53:05 +0530 (Tue, 10 Jan 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("VMware Tools Detection (Mac OS X SSH Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  VMware Tools on Mac OS X.

  The script logs in via ssh, searches for folder 'Uninstall VMware Tools.app' and
  queries the related 'info.plist' file for string 'CFBundleShortVersionString'
  via command line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

vmtoolVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Library/" +
            "Application\ Support/VMware\ Tools/Uninstall\ VMware\ Tools.app/Contents/Info " +
            "CFBundleShortVersionString"));

close(sock);

if(isnull(vmtoolVer) || "does not exist" >< vmtoolVer){
  exit(0);
}

set_kb_item(name: "VMwareTools/MacOSX/Version", value:vmtoolVer);

cpe = build_cpe(value:vmtoolVer, exp:"^([0-9.]+)", base:"cpe:/a:vmware:tools:");
if(isnull(cpe))
  cpe='cpe:/a:vmware:tools';

register_product(cpe:cpe, location:'/Library');

log_message(data: build_detection_report(app: "VMware Tools",
                                         version: vmtoolVer,
                                         install: "/Library",
                                         cpe: cpe,
                                         concluded: vmtoolVer));
exit(0);
