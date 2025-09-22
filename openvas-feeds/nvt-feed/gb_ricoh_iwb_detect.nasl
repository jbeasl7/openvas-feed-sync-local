# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141736");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-11-29 12:16:58 +0700 (Thu, 29 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("RICOH Interactive Whiteboard Detection");

  script_tag(name:"summary", value:"Detection of RICOH Interactive Witeboard.

  The script sends a connection request to the server and attempts to detect RICOH Interactive Whiteboard and to
  extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("IWB/banner");

  script_xref(name:"URL", value:"https://www.ricoh-usa.com/en/products/pl/equipment/interactive-whiteboards/");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

res = http_get_cache(port: port, item: "/");
if ("Server: IWB Web-Server" >!< res || 'logo_product">interactive whiteboard' >!< res)
  exit(0);

# <dd>D5520</dd>
mod = eregmatch(pattern: "<dd>(D[0-9]+)</dd>", string: res);
if (!isnull(mod[1])) {
  model = mod[1];
  set_kb_item(name: "ricoh_iwb/model", value: model);
  os_cpe = 'cpe:/o:ricoh:iwb_' + tolower(model) + '_firmware';
  hw_cpe = 'cpe:/h:ricoh:iwb_' + tolower(model);
}
else {
  os_cpe = 'cpe:/o:ricoh:iwb_firmware';
  hw_cpe = 'cpe:/h:ricoh:iwb';
}

# <dd>3.1.20015.0</dd>
vers = eregmatch(pattern: "<dd>([0-9.]+)</dd>", string: res);
if (!isnull(vers[1])) {
  version = vers[1];
  os_cpe += ':' + version;
}

set_kb_item(name: "ricoh_iwb/detected", value: TRUE);

register_product(cpe: os_cpe, location: "/", port: port, service: "www");
register_product(cpe: hw_cpe, location: "/", port: port, service: "www");
os_register_and_report(os: "RICOH Interactive Whiteboard Firmware", cpe: os_cpe,
                       desc: "RICOH Interactive Whiteboard Detection", runs_key: "unixoide");

report = build_detection_report(app: "RICOH Interactive Whiteboard " + model + " Firmware", version: version,
                                install: "/", cpe: os_cpe, concluded: vers[0]);
report += '\n\n';
report += build_detection_report(app: "RICOH Interactive Whiteboard " + model + " Device", skip_version: TRUE,
                                 install: "/", cpe: hw_cpe);

log_message(port: port, data: report);

exit(0);
