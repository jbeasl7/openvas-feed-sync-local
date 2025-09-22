# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804419");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-04-08 13:04:12 +0530 (Tue, 08 Apr 2014)");
  script_name("McAfee Web Gateway (MWG) Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of McAfee Web Gateway (MWG).

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("McAfee_Web_Gateway/banner");
  script_require_ports("Services/www", 8080);

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:8080);

banner = http_get_remote_headers(port:port);
if(!banner)
  exit(0);

if(!concl = egrep(string:banner, pattern:"McAfee Web Gateway", icase:FALSE))
  exit(0);

concl = chomp(concl);
version = "unknown";

vers = eregmatch(pattern:"McAfee Web Gateway ([0-9.]+)", string:banner);
if(vers[1]) {
  version = vers[1];
  concl = vers[0];
}

set_kb_item(name:"www/" + port + "/McAfee/Web/Gateway", value:version);
set_kb_item(name:"McAfee/Web/Gateway/installed", value:TRUE);

cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:mcafee:web_gateway:");
if(!cpe)
  cpe = "cpe:/a:mcafee:web_gateway";

register_product(cpe:cpe, location:port + "/tcp", port:port, service:"www");

log_message(data:build_detection_report(app:"McAfee Web Gateway",
                                        version:version,
                                        install:port + "/tcp",
                                        cpe:cpe,
                                        concluded:concl),
                                        port:port);
exit(0);
