# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804302");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-02-03 13:00:16 +0530 (Mon, 03 Feb 2014)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Adobe Digital Edition Detection (Mac OS X SSH Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  Adobe Digital Edition on MAC.

  The script logs in via ssh, gets the version by using a command and set
  it in the KB item.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone AG");
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

ediVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
            "Adobe\ Digital\ Editions.app/Contents/Info " +
            "CFBundleShortVersionString"));

close(sock);

if(isnull(ediVer) || "does not exist" >< ediVer){
  exit(0);
}

set_kb_item(name: "AdobeDigitalEdition/MacOSX/Version", value:ediVer);

cpe = build_cpe(value:ediVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:digital_editions:");
if(isnull(cpe))
  cpe='cpe:/a:adobe:digital_editions';

register_product(cpe:cpe, location:'/Applications/Adobe Digital Editions.app');

log_message(data: build_detection_report(app: "Adobe Digital Editions",
                                         version: ediVer,
                                         install: "/Applications/Adobe Digital Editions.app",
                                         cpe: cpe,
                                         concluded: ediVer));
