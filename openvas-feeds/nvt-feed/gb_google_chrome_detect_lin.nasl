# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801446");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");
  script_name("Google Chrome Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rpms_or_debs/gathered");

  script_tag(name:"summary", value:"SSH login-based detection of Google Chrome.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

rpms = get_kb_item("ssh/login/rpms");
if(rpms && rpms =~ "google-chrome") {
  vers = eregmatch(pattern:"google-chrome.?([a-zA-z])*.?([0-9.]+)", string:rpms);
  if(vers[2]) {
    version = vers[2];
    concluded = "RPM package query: " + vers[0];
  }
}

if(!version) {
  debs = get_kb_item("ssh/login/packages");
  if(debs && debs =~ "google-chrome") {
    match = egrep(pattern:"google-chrome", string:debs);
    match = chomp(match);
    if(match) {
      vers = eregmatch(pattern:"([0-9.]+)", string:match);
      if(vers[1]) {
        version = vers[1];
        concluded = "DPKG package query: " + vers[0];
      }
    }
  }
}

if(version) {

  path = "/usr/bin/google-chrome";

  set_kb_item(name:"Google-Chrome/Linux/Ver", value:version);
  set_kb_item(name:"google/chrome/detected", value:TRUE);

  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:google:chrome:");
  if(!cpe)
    cpe = "cpe:/a:google:chrome";

  register_product(cpe:cpe, location:path, port:0, service:"ssh-login");

  log_message(data:build_detection_report(app:"Google Chrome",
                                          version:version,
                                          install:path,
                                          cpe:cpe,
                                          concluded:concluded),
              port:0);
}

exit(0);