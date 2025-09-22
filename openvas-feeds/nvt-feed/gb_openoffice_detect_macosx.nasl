# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805609");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2015-06-01 12:25:40 +0530 (Mon, 01 Jun 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("OpenOffice Detection (Mac OS X SSH Login)");

  script_tag(name:"summary", value:"Detects the installed version of OpenOffice.

  The script logs in via ssh, searches for folder 'OpenOffice.app' and
  queries the related 'info.plist' file for string 'CFBundleVersion' via command
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
if(!sock)
{
  exit(0);
}

if (!get_kb_item("ssh/login/osx_name"))
{
  close(sock);
  exit(0);
}

Ver = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
             "OpenOffice.app/Contents/Info CFBundleGetInfoString"));
Ver = eregmatch(pattern:"OpenOffice ([0-9.]+).*(Build:([0-9.]+))?", string:Ver);
if(isnull(Ver) || "does not exist" >< Ver){
   exit(0);
}
set_kb_item(name: "OpenOffice/MacOSX/Version", value:Ver[1]);

cpe1 = build_cpe(value:Ver[1], exp:"^([0-9.]+)", base:"cpe:/a:apache:openoffice:");
cpe2 = build_cpe(value:Ver[1], exp:"^([0-9.]+)", base:"cpe:/a:openoffice:openoffice.org:");
if(isnull(cpe1)){
  cpe1 = "cpe:/a:apache:openoffice";
  cpe2 = "cpe:/a:openoffice:openoffice.org";
}
path = '/Applications/OpenOffice.app/';

register_product(cpe:cpe1, location:path);
register_product(cpe:cpe2, location:path);

log_message(data: build_detection_report(app: "OpenOffice", version: Ver[1],
                                         install: "/Applications/OpenOffice.app",
                                         cpe: cpe1,
                                         concluded: Ver[1]));
