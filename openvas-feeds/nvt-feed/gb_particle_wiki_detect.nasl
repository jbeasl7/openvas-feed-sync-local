# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100836");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-10-04 14:08:22 +0200 (Mon, 04 Oct 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Particle Wiki Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Particle Wiki.");

  script_xref(name:"URL", value:"http://www.particlesoft.net/particlewiki/");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default:80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/wiki", http_cgi_dirs(port: port))) {
  install = dir;

  if (dir == "/")
    dir = "";

  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );

  if ("Powered by Particle Wiki" >< buf && "Particle Soft" >< buf) {
    version = "unknown";

    # Powered by Particle Wiki 1.0.3
    vers = eregmatch(string: buf, pattern: "Powered by Particle Wiki ([0-9.]+)", icase: TRUE);
    if (!isnull(vers[1]))
       version = vers[1];

    set_kb_item(name: "particle_wiki/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:particle_soft:particle_wiki:");
    if (!cpe)
      cpe = "cpe:/a:particle_soft:particle_wiki";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Particle Wiki", version: version, install: install,
                                             cpe: cpe, concluded: vers[0]),
                port: port);
    exit(0);
  }
}

exit(0);
