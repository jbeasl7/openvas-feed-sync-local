# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107223");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-06-12 06:40:16 +0200 (Mon, 12 Jun 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Arachni Version Detection");
  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of Arachni.

  The script detects the version of Arachni remote host and sets the KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

Port = http_get_port(default: 80);
url = '/d/users/sign_in';

req = http_get(port: Port, item: url);
res = http_keepalive_send_recv(port: Port, data: req);

if (res !~ "HTTP/1\.[01] 200" && ">Arachni v" >< res && "- WebUI v" >< res) {

  Ver = "unknown";

  tmpVer = eregmatch(pattern: "Arachni v([0-9.]+)  - WebUI v([0-9.]+)",
                    string: res);
  if (tmpVer[1]) {
    Ver = tmpVer[1];
    set_kb_item(name: "arachni/version", value: Ver);

    if (tmpVer[2]) {
      set_kb_item(name: "arachni/webui", value: tmpVer[2]);
    }
  }

  set_kb_item(name: "arachni/installed", value: TRUE);

  cpe = build_cpe(value: Ver, exp: "^([0-9.]+)", base: "cpe:/a:arachni:arachni:");

  if(!cpe)
    cpe = 'cpe:/a:arachni:arachni';

  register_product(cpe:cpe, location: "/", port: Port, service:"www");

  log_message(data:build_detection_report(app: "Arachni",
                                          version: Ver,
                                          install: "/",
                                          cpe: cpe,
                                          concluded: tmpVer[0]),
                                          port: Port);
}

exit(0);
