# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.139919");
  script_version("2026-11-06T05:39:10+0000");
  script_tag(name:"last_modification", value:"2026-11-06 05:39:10 +0000 (Fri, 06 Nov 2026)");
  script_tag(name:"creation_date", value:"2026-09-18 08:14:14 +0100 (Fri, 18 Sep 2026)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("TinyWeb Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80, 443);
  script_mandatory_keys("TinyWeb/banner");

  script_tag(name:"summary", value:"HTTP based detection of TinyWeb.");

  script_xref(name:"URL", value:"https://github.com/maximmasiutin/TinyWeb");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("os_func.inc");
include("port_service_func.inc");
include("cpe.inc");

port = http_get_port(default: 443);

banner = http_get_remote_headers(port: port);

# Server: TinyWeb/2.02
# Server: TinyWeb/1.97
# Server: TinyWeb/1.94
if(concl = egrep(string: banner, pattern: "^Server\s*:.*TinyWeb\/([0-9.]+)", icase: FALSE)) {

  concl = chomp(concl);

  version = "unknown";
  location = "/";

  vers = eregmatch(string: banner, pattern: "Server\s*:.*TinyWeb\/([0-9.]+)");
  if(vers[1])
    version = vers[1];

  set_kb_item(name: "TinyWeb/detected", value: TRUE);
  set_kb_item(name: "TinyWeb/http/detected", value: TRUE);
  set_kb_item(name: "TinyWeb/http/port", value: port);

  cpe = build_cpe(value: version, exp: "([0-9.+]+)", base: "cpe:/a:ritlabs:tinyweb:");
  if(!cpe)
    cpe = "cpe:/a:ritlabs:tinyweb";

  os_register_and_report(os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows",
                         port: port, desc: "TinyWeb Detection (HTTP)", runs_key: "windows");

  register_product(cpe: cpe, location: location, port: port, service: "www");

  log_message(data: build_detection_report(app: "TinyWeb",
                                           version: version,
                                           install: location,
                                           cpe: cpe,
                                           concluded: concl),
              port: port);
}

exit(0);
