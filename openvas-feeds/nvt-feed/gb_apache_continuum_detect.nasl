# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103073");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-02-11 13:54:50 +0100 (Fri, 11 Feb 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Apache Continuum Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://continuum.apache.org/");

  script_tag(name:"summary", value:"Detection of Apache Continuum.

  The script sends a connection request to the server and attempts to detect the presence of Apache Continuum and to
  extract its version");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8080);

url = "/continuum/about.action";
req = http_get(item: url, port: port);
buf = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);
if (!buf)
  exit(0);

if ("Continuum - About" >< buf && "<h3>About Continuum</h3>" >< buf) {

  buf_lines = split(buf);
  install = "/continuum";
  version = "unknown";

  x=0;
  foreach line (buf_lines) {
    x++;

    if ("Version:</label>" >< line) {
      vers = eregmatch(string: buf_lines[x], pattern: "([0-9.]+)</td>",icase:TRUE);
      if (!isnull(vers[1])) {
        version = vers[1];
        set_kb_item(name: "apache_continuum/version", value: version);
      }
    }

    if ("Build Number:</label>" >< line) {
      b = eregmatch(string: buf_lines[x], pattern: "([0-9]+)</td>",icase:TRUE);
      if (!isnull(b[1])) {
        build = b[1];
        set_kb_item(name: "apache_continuum/build", value: build);
      }
      break;
    }
  }

  set_kb_item(name: "apache_continuum/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:apache:continuum:");
  if (!cpe)
    cpe = "cpe:/a:apache:continuum";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "Apache Continuum", version: version + " Build: " + build,
                                           install: install, cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
