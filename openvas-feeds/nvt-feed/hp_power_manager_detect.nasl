# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:embedthis:goahead";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100456");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-01-20 19:30:24 +0100 (Wed, 20 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("HP Power Manager Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_embedthis_goahead_http_detect.nasl");
  script_mandatory_keys("embedthis/goahead/http/detected");

  script_xref(name:"URL", value:"https://www.hpe.com/");

  script_tag(name:"summary", value:"HTTP based detection of HP Power Manager.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

# nb: No get_app_location() as goahead is only used within this product and there is no point
# in linking to the detection of it.
if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

url = "/CPage/About_English.asp";

buf = http_get_cache(item:url, port:port);

if ("About HP Power Manager" >< buf) {
  vers = "unknown";

  version = eregmatch(string: buf, pattern: "HP Power Manager ([0-9.]+)[ ]*([(Build 0-9)]*)",icase:TRUE);
  if (!isnull(version[1])) {
    if ("Build" >< version[2]) {
      build = eregmatch(pattern: "\(Build ([0-9]+)\)", string: version[2]);
      vers = version[1] + "." + build[1];
    } else
      vers = version[1];
    concUrl = url;
  }

  set_kb_item(name: "hp_power_manager/detected", value: TRUE);

  cpe = build_cpe(value: vers, exp: "^([0-9.]+)", base: "cpe:/a:hp:power_manager:");
  if (!cpe)
    cpe = "cpe:/a:hp:power_manager";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "HP Power Manager", version: vers, install: "/", cpe: cpe,
                                           concluded: version[0], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
