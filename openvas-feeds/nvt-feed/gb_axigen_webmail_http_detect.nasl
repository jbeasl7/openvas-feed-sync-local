# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100176");
  script_version("2024-02-23T05:07:12+0000");
  script_tag(name:"last_modification", value:"2024-02-23 05:07:12 +0000 (Fri, 23 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Axigen WebMail/WebAdmin Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Axigen WebMail");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

axPort = http_get_port(default:80);

url = "/index.hsp?login=";

buf = http_get_cache(port: axPort, item: url);

if (egrep(pattern: 'Server: Axigen-.*', string: buf, icase: TRUE)) {
  app_found = eregmatch(string: buf, pattern: 'Server: Axigen-(Webmail|Webadmin)',icase:TRUE);
  if (!isnull(app_found[1]))
    axigen_app = app_found[1];

  vers = "unknown";

  version = eregmatch(string: buf, pattern: '<title>AXIGEN Web[mail|admin]+[^0-9]+([0-9.]+)</title>',icase:TRUE);

  if (!isnull(version[1]))
    vers=version[1];
  else
  {
    version = eregmatch(string: buf, pattern: ">[V|v]ersion ([0-9.]+)<");
    if (!isnull(version[1]))
      vers = version[1];
    else {
      # e.g. lib_login.js?v=1000
      version = eregmatch(string: buf, pattern: "\?v=([0-9.]+)");
      vers = substr(version[1], 0,1) + "." + substr(version[1], 2, 2) + "." + substr(version[1], 3, 3) + "." + substr(version[1], 4, 5);
      if (!isnull(version[1]) && strlen(version[1]) == 4) {
        vers = version[1];
        vers = substr(vers, 0, 1) + '.' + vers[2] + '.' + vers[3];
      }
    }
  }

  set_kb_item(name: "axigen/detected", value: TRUE);

  cpe = build_cpe(value: vers, exp: "^([0-9.]+)", base: "cpe:/a:axigen:axigen_mail_server:");
  if (isnull(cpe))
    cpe = "cpe:/a:axigen:axigen_mail_server";

  register_product(cpe: cpe, location: "/", port: axPort, service: "www");

  log_message(data: build_detection_report(app:"Axigen " + axigen_app, version: vers, install: "/",
                                           cpe: cpe, concluded: version[0]),
              port: axPort);
  exit(0);
}

exit(0);
