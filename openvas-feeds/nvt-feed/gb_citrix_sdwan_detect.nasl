# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141651");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-11-06 16:12:43 +0700 (Tue, 06 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Citrix SD-WAN Detection");

  script_tag(name:"summary", value:"Detection of Citrix SD-WAN.

The script sends a connection request to the server and attempts to detect Citrix SD-WAN and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.citrix.com/products/citrix-sd-wan/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

res = http_get_cache(port: port, item: "/cgi-bin/login.cgi");

if ("/vw/css/vw.css" >< res && "citrix_login_logo" >< res && res =~ "<title>[^|]+| Login</title>") {
  version = "unknown";

  # <link href="/vw/css/vw.css?R10_0_4_8_707998"
  vers = eregmatch(pattern: "vw.css\?R([0-9_]+)", string: res);
  if (!isnull(vers[1]))
    version = str_replace(string: vers[1], find: "_", replace: ".");

  set_kb_item(name: "citrix_sdwan/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:citrix:sd-wan:");
  if (!cpe)
    cpe = 'cpe:/a:citrix:sd-wan';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Citrix SD-WAN", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
