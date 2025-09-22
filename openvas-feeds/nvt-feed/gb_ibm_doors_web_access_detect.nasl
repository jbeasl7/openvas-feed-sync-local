# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140740");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-02-02 11:32:17 +0700 (Fri, 02 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IBM Rational DOORS Web Access Detection");

  script_tag(name:"summary", value:"Detection of IBM Rational DOORS Web Access.

The script sends a connection request to the server and attempts to detect IBM Rational DOORS Web Access and to
extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.ibm.com/us-en/marketplace/rational-doors");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

res = http_get_cache(port: port, item: "/dwa/welcome/welcome.jsp");

if ("<title>Login to Rational DOORS Web Access</title>" >< res && "DOORS Web Access are trademarks" >< res) {
  version = "unknown";

  # Version 9.6.1.9 (Build 96633) </span>
  vers = eregmatch(pattern: "Version ([0-9.]+) \(Build", string: res);
  if (!isnull(vers[1]))
    version = vers[1];
  else {
    url = "/dwa/about.jsp";
    req = http_get(port: port, item: url);
    res = http_keepalive_send_recv(port: port, data: req);

    vers = eregmatch(pattern: "Version ([0-9.]+) \(Build", string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      concUrl = url;
    }
  }

  set_kb_item(name: "ibm_doors_webaccess/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "([0-9.]+)", base: "cpe:/a:ibm:rational_doors_web_access:");
  if (!cpe)
    cpe = 'cpe:/a:ibm:rational_doors_web_access';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "IBM Rational DOORS Web Access", version: version, install: "/",
                                           cpe: cpe, concluded: vers[0], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
