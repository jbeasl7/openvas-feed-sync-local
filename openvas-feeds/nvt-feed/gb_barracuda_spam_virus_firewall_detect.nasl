# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100846");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-10-06 12:55:58 +0200 (Wed, 06 Oct 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Barracuda Spam & Virus Firewall Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of Barracuda Spam & Virus Firewall

  The script sends a connection request to the server and attempts to detect the presence of Barracuda Spam &
  Virus Firewall and to extract its version");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8000);
  script_mandatory_keys("BarracudaHTTP/banner");

  script_xref(name:"URL", value:"https://www.barracuda.com/products/emailsecuritygateway");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default: 8000);

banner = http_get_remote_headers(port: port);
if ("Server: BarracudaHTTP" >!< banner)
  exit(0);

url = "/cgi-mod/index.cgi";
req = http_get(item: url, port: port);
buf = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

if ("<title>Barracuda Spam & Virus Firewall: Welcome" >< buf && "Barracuda Login Page" >< buf) {
  version = "unknown";
  vers = eregmatch(string: buf, pattern: "/barracuda.css\?v=([0-9.]+)", icase: TRUE);
  if (!isnull(vers[1]) )
    version = vers[1];

  set_kb_item(name: "barracuda_spam_virus_fw/installed", value: TRUE);
  if (version != "unknown")
    set_kb_item(name: "barracuda_spam_virus_fw/version", value: version);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/h:barracuda_networks:barracuda_spam_firewall:");
  if (!cpe)
    cpe = "cpe:/h:barracuda_networks:barracuda_spam_firewall";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Barracuda Spam and Virus Firewall", version: version,
                                           install: "/", cpe: cpe, concluded: vers[0]),
              port: port);

  exit(0);
}

exit(0);

