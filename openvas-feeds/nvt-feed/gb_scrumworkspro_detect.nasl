# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107246");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-09-25 16:22:38 +0700 (Mon, 25 Sep 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Scrumworks Pro Detection");

  script_tag(name:"summary", value:"Detection of ScrumWorks Pro.

The script sends a connection request to the server and attempts to detect Scrumworks Pro and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");

  script_require_ports("Services/www", 8080, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.collab.net/products/scrumworks");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8080);

res = http_get_cache(port: port, item: "/scrumworks/login");

if ('<title>Welcome to ScrumWorks' >< res && 'scrumworkspro' >< res)
{
    install = "/scrumworks/login";

    version = "unknown";
    ver = eregmatch( pattern: 'ScrumWorks version ([0-9.]+) [(]([0-9-]+ [0-9:]+ r[0-9]+)[)]', string: res);
    if (!isnull(ver[1]))
    {
       version = ver[1];
    }
    if (!isnull(ver[2]))
    {
       build = ver[2];
       set_kb_item(name: "scrumworkspro/build", value: build);
    }

    set_kb_item(name: "scrumworkspro/installed", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:collabnet:scrumworkspro:");

    if (!cpe)
    cpe = 'cpe:/a:collabnet:scrumworkspro';

    register_product(cpe: cpe, location: install, port: port, service: "www");

     log_message(data: build_detection_report(app: "ScrumWorks Pro", version: version, install: install,
                                           cpe: cpe, concluded: ver[0]),
                port: port);
     exit(0);
}

exit(0);
