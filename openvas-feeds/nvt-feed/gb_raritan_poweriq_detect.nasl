# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106817");
  script_version("2023-06-22T13:00:03+0000");
  script_tag(name:"last_modification", value:"2023-06-22 13:00:03 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2017-05-22 10:12:10 +0700 (Mon, 22 May 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Raritan PowerIQ Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Raritan PowerIQ.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.raritan.com/products/dcim-software/power-iq");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default: 443);

url = "/license/records";
res = http_get_cache(port: port, item: url);

if (egrep(pattern: "^HTTP/1\.[01] 302", string: res)) {
  data = "sort=id&dir=ASC";
  req = http_post_put_req(port: port, url: url, data: data, add_headers: make_array("X-Requested-With", "XMLHttpRequest"));
  res = http_keepalive_send_recv(port: port, data: req);
}

if ('"feature":"Power IQ"' >< res) {
  version = "unknown";
  install = "/";

  cpe = "cpe:/a:raritan:power_iq";

  set_kb_item(name: "raritan_poweriq/detected", value: TRUE);

  register_product(cpe: cpe, location: install, port: port);

  log_message(data: build_detection_report(app: "Raritan PowerIQ", version: version, install: install, cpe: cpe));
  exit(0);
}

exit(0);
