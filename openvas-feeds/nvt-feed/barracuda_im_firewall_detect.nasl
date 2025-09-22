# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100392");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-11 12:55:06 +0100 (Fri, 11 Dec 2009)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("Barracuda IM Firewall Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("BarracudaHTTP/banner");

  script_tag(name:"summary", value:"This host is running Barracuda IM Firewall. Barracuda IM Firewall control and
  manage internal and external instant messaging (IM) traffic.");

  script_xref(name:"URL", value:"http://www.barracudanetworks.com/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port: port);
if("Server: BarracudaHTTP" >!< banner) exit(0);

url = "/cgi-mod/index.cgi";
buf = http_get_cache(port: port, item: url);

if (egrep(pattern: "<title>Barracuda IM Firewall", string: buf, icase: TRUE)) {
  vers = "unknown";

  version = eregmatch(string: buf, pattern: "barracuda\.css\?v=([0-9.]+)", icase: TRUE);
  if (!isnull(version[1]))
    vers = chomp(version[1]);

  set_kb_item(name: "barracuda_im_firewall/detected", value: TRUE);
  set_kb_item(name: "www/" + port + "/barracuda_im_firewall", value: vers);

  cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/h:barracuda_networks:barracuda_im_firewall:");
  if (!cpe)
    cpe = "cpe:/h:barracuda_networks:barracuda_im_firewall";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Barracuda IM Firewall", version: vers, install: "/", cpe: cpe,
                                           concluded: version[0]),
              port: port);
  exit(0);
}

exit(0);
