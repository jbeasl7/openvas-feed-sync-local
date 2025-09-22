# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802318");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2011-08-10 13:49:51 +0200 (Wed, 10 Aug 2011)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Google Chrome Detection (Mac OS X SSH Login)");

  script_tag(name:"summary", value:"SSH login-based detection of Google Chrome.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
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

chromeVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
             "Google\ Chrome.app/Contents/Info CFBundleShortVersionString"));

close(sock);

if(isnull(chromeVer) || "does not exist" >< chromeVer){
  exit(0);
}

set_kb_item(name:"GoogleChrome/MacOSX/Version", value:chromeVer);
set_kb_item(name:"google/chrome/detected", value:TRUE);

cpe = build_cpe(value:chromeVer, exp:"^([0-9.]+)", base:"cpe:/a:google:chrome:");
if(!cpe)
  cpe = "cpe:/a:google:chrome";

register_product(cpe:cpe, location:"/Applications/Google Chrome.app", port:0, service:"ssh-login");

log_message(data:build_detection_report(app:"Google Chrome",
                                        version:chromeVer,
                                        install:"/Applications/Google Chrome.app",
                                        cpe:cpe,
                                        concluded:chromeVer),
            port:0);

exit(0);
