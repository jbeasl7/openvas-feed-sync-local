# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:embedthis:goahead";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106740");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-04-11 13:52:39 +0200 (Tue, 11 Apr 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Moxa AWK Series Devices Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Moxa AWK Series Devices (Industrial
  Wireless LAN Solutions).");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_embedthis_goahead_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("embedthis/goahead/http/detected");

  script_xref(name:"URL", value:"http://www.moxa.com/product/Industrial_Wireless_LAN.htm");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

# nb: No get_app_location() as goahead is only used within this product and there is no point
# in linking to the detection of it.
if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

res = http_get_cache(port: port, item: "/Login.asp");

if ("<title>Moxa AWK-" >< res && "Password508=" >< res && "llogin.gif" >< res) {
  version = "unknown";

  mod = eregmatch(pattern: "Moxa (AWK-[^ ]+)", string: res);
  if (isnull(mod[1]))
    exit(0);

  model = mod[1];

  set_kb_item(name: "moxa_awk/detected", value: TRUE);
  set_kb_item(name: "moxa_awk/model", value: model);

  cpe = "cpe:/h:moxa:" + tolower(model);

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: 'The remote host is a Moxa ' + model + '\n\nCPE: ' + cpe, port: port);
  exit(0);
}

exit(0);
