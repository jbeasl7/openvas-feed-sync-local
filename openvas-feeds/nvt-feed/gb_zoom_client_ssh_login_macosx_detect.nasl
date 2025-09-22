# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814355");
  script_version("2024-06-14T05:05:48+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-14 05:05:48 +0000 (Fri, 14 Jun 2024)");
  script_tag(name:"creation_date", value:"2018-12-06 18:04:33 +0530 (Thu, 06 Dec 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Zoom Client / Desktop / Workplace Detection (Mac OS X SSH Login)");

  script_tag(name:"summary", value:"SSH login-based detection of the Zoom Client / Desktop / Workplace.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

zoomVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/zoom.us.app/Contents/Info CFBundleShortVersionString"));
close(sock);
if(isnull(zoomVer) || "does not exist" >< zoomVer)
  exit(0);

set_kb_item(name:"zoom/client/detected", value:TRUE);
set_kb_item(name:"zoom/client/mac/detected", value:TRUE);

cpe = build_cpe(value:zoomVer, exp:"^([0-9.]+)", base:"cpe:/a:zoom:zoom:");
if(!cpe)
  cpe = "cpe:/a:zoom:zoom";

  # nb:
  # - NVD is currently using two different CPEs because Zoom has some inconsistencies in their
  #   client naming / renamed the Client a few times. We register both just to be sure.
  # - In 2024 the client was renamed once more to "Zoom Workplace Desktop App" so in total we have
  #   now the following different namings seen in advisories:
  #   - Zoom Workplace Desktop App
  #   - Zoom Desktop Client
  #   - Zoom Client for Meetings
  #   - macOS Zoom Client
cpe2 = build_cpe(value:zoomVer, exp:"^([0-9.]+)", base:"cpe:/a:zoom:meetings:");
if(!cpe2)
  cpe2 = "cpe:/a:zoom:meetings";

register_product(cpe:cpe, location:"/Applications/zoom.us.app", service:"ssh-login", port:0);
register_product(cpe:cpe2, location:"/Applications/zoom.us.app", service:"ssh-login", port:0);

report = build_detection_report(app:"Zoom Client / Desktop / Workplace",
                                version:zoomVer,
                                install:"/Applications/zoom.us.app",
                                cpe:cpe,
                                concluded:zoomVer);

log_message(port:0, data:report);

exit(0);
