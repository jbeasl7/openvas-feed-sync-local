# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140604");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-12-14 13:28:21 +0700 (Thu, 14 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("TIBCO tibbr Detection");

  script_tag(name:"summary", value:"Detection of TIBCO tibbr.

The script sends a connection request to the server and attempts to detect TIBCO tibbr and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.tibbr.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

res = http_get_cache(port: port, item: "/tibbr/web/login");

if ("h2>Welcome to tibbr</h2>" >< res && '"company_name":"TIBCO Software Inc."' >< res) {
  version = "unknown";

  # "version":"6.0.1 HF7"
  # currently don't see a possibility to distinguish between 'community' and 'enterprise'
  vers = eregmatch(pattern: '"version":"([^"]+)"', string: res);
  if (!isnull(vers[1])) {
    tmp_vers = split(vers[1], sep: ' ', keep: FALSE);
    version = tmp_vers[0];
    if (!isnull(tmp_vers[1])) {
      hotfix = tmp_vers[1];
      set_kb_item(name: "tibbr/hotfix", value: hotfix);
      extra = "Hotfix: " + hotfix;
    }
  }

  set_kb_item(name: "tibbr/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:tibco:tibbr:");
  if (!cpe)
    cpe = 'cpe:/a:tibco:tibbr';

  register_product(cpe: cpe, location: "/tibbr", port: port, service: "www");

  log_message(data: build_detection_report(app: "TIBCO tibbr", version: version, install: "/tibbr", cpe: cpe,
                                           concluded: vers[0], extra: extra),
              port: port);
  exit(0);
}

exit(0);
