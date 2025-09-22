# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141467");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-09-11 10:50:41 +0700 (Tue, 11 Sep 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Monit Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of Monit.

  The script sends a connection request to the server and attempts to detect Monit and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080, 8181);
  script_mandatory_keys("monit/banner");

  script_xref(name:"URL", value:"https://mmonit.com/monit/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8080);

banner = http_get_remote_headers(port: port);
res = http_get_cache(port: port, item: "/");

if (banner !~ "Server\s*:\s*monit" && banner !~ 'WWW-Authenticate\\s*:\\s*Basic\\s+realm="monit"' &&
    "You are not authorized to access monit." >!< res && res !~ "https?://(www\.)?mmonit\.com/monit")
  exit(0);

version = "unknown";

# server: monit 5.25.2
# Server: monit 5.6
vers = eregmatch(pattern: "Server\s*:\s*monit ([0-9.]+)", string: banner, icase: TRUE);
if (!isnull(vers[1])) {
  version = vers[1];
  concluded = vers[0];
}

if (version == "unknown") {

  # nb: A few systems are using Monit behind a reverse proxy without the Server: monit banner.
  # For such systems we still can grab the Version from the 401 page exposing the version like:
  # <a href='http://mmonit.com/monit/'><font size=-1>monit 5.16</font>
  # <a href='http://mmonit.com/monit/'><font size=-1>monit 5.20.0</font>

  vers = eregmatch(pattern: ">monit ([0-9.]+)<", string: res, icase: FALSE);
  if (!isnull(vers[1])) {
    version = vers[1];
    concluded = vers[0];
  }
}

if (version == "unknown") {
  concl = egrep(pattern: '(Server\\s*:\\s*monit|WWW-Authenticate\\s*:\\s*Basic\\s+realm="monit")', string: banner, icase: TRUE);
  if (concl)
    concluded = concl;
}

set_kb_item(name: "monit/detected", value: TRUE);

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:tildeslash:monit:");
if (!cpe)
  cpe = "cpe:/a:tildeslash:monit";

os_register_and_report(os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: "HTTP banner / authorization header", desc: "Monit Detection (HTTP)", runs_key: "unixoide");

register_product(cpe: cpe, location: "/", port: port, service: "www");

log_message(data: build_detection_report(app: "Monit", version: version, install: "/", cpe: cpe,
                                         concluded: concluded),
            port: port);

exit(0);
