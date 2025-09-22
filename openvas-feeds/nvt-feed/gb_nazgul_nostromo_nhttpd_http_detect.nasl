# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.135009");
  script_version("2025-06-06T05:41:39+0000");
  script_tag(name:"last_modification", value:"2025-06-06 05:41:39 +0000 (Fri, 06 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-04-28 06:50:03 +0000 (Mon, 28 Apr 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Nazgul Nostromo nhttpd Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("nostromo/banner");

  script_tag(name:"summary", value:"HTTP based detection of Nazgul Nostromo nhttpd.");

  script_xref(name:"URL", value:"https://www.nazgul.ch/dev_nostromo.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!banner = http_get_remote_headers(port: port))
  exit(0);

if (concl = egrep(string: banner, pattern:"^[Ss]erver\s*:\s*[Nn]ostromo", icase: FALSE)) {
  concl = chomp(concl);

  version = "unknown";
  install = "/";
  conclUrl = http_report_vuln_url(port: port, url: install, url_only: TRUE);

  # Server: nostromo 1.8.4
  # Server: nostromo 1.9.4
  # Server: nostromo 2.1
  vers = eregmatch(pattern: "[Ss]erver\s*:\s*[Nn]ostromo ([0-9.]+)", string: banner, icase: FALSE);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "nazgul/nostromo_nhttpd/detected", value: TRUE);
  set_kb_item(name: "nazgul/nostromo_nhttpd/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:nazgul:nostromo_nhttpd:");
  if (!cpe)
    cpe = "cpe:/a:nazgul:nostromo_nhttpd";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "Nazgul Nostromo nhttpd",
                                           version: version,
                                           install: install,
                                           cpe: cpe,
                                           concluded: concl,
                                           concludedUrl: conclUrl),
              port: port);
}

exit(0);
