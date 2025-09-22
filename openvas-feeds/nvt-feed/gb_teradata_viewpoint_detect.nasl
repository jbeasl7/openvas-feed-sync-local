# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141900");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2019-01-22 12:01:36 +0700 (Tue, 22 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Teradata Viewpoint Detection");

  script_tag(name:"summary", value:"Detection of Teradata Viewpoint.

The script sends a connection request to the server and attempts to detect Teradata Viewpoint and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.teradata.com/Products/Ecosystem-Management/IntelliSphere/Viewpoint");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

res = http_get_cache(port: port, item: "/login.html");

if ("<title>Teradata Viewpoint</title>" >< res && "viewpoint.css" >< res) {
  version = "unknown";

  # Teradata Viewpoint 16.10.00.02-b108
  vers = eregmatch(pattern: "Teradata Viewpoint ([0-9b.-]+)", string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "teradata/viewpoint/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9b.-]+)", base: "cpe:/a:teradata:viewpoint:");
  if (!cpe)
    cpe = 'cpe:/a:teradata:viewpoint';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Teradata Viewpoint", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
