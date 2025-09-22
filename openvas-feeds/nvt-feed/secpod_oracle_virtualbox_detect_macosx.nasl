# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902788");
  script_version("2025-09-19T05:38:25+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2012-01-25 11:25:41 +0530 (Wed, 25 Jan 2012)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Oracle VirtualBox Detection (Mac OS X SSH Login)");

  script_tag(name:"summary", value:"Detects the installed version of Oracle VM VirtualBox.

The script logs in via ssh, searches for folder 'VirtualBox.app' and
queries the related 'info.plist' file for string 'CFBundleShortVersionString'
via command line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}

include("version_func.inc");
include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

ver = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/VirtualBox.app/Contents/Info CFBundleShortVersionString"));

close(sock);

if(isnull(ver) || "does not exist" >< ver)
  exit(0);

if(version_is_less(version:ver, test_version:"3.2.0")) {
  cpe = build_cpe(value:ver, exp:"^([0-9.]+)", base:"cpe:/a:sun:virtualbox:");
  if(!cpe)
    cpe = "cpe:/a:sun:virtualbox";

  register_product(cpe:cpe, location:"/Applications/VirtualBox.app");
} else {
  cpe = build_cpe(value:ver, exp:"^([0-9.]+)", base:"cpe:/a:oracle:vm_virtualbox:");
  if(!cpe)
    cpe = "cpe:/a:oracle:vm_virtualbox";

  register_product(cpe:cpe, location:"/Applications/VirtualBox.app");
}

set_kb_item(name: "Oracle/VirtualBox/MacOSX/Version", value:ver);
log_message(data: build_detection_report(app: "Oracle VirtualBox",
                                         version: ver,
                                         install: "/Applications/VirtualBox.app",
                                         cpe: cpe,
                                         concluded: ver));
