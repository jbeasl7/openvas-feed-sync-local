# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809774");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-12-30 14:43:15 +0530 (Fri, 30 Dec 2016)");
  script_name("NETGEAR WNR2000 Router Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of NETGEAR WNR2000 Routers

  The script sends a connection request to the server and attempts to
  detect the presence of NETGEAR WNR2000 Routers.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wnr2000/banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if(!banner)
  exit(0);

if(concl = egrep(string:banner, pattern:'WWW-Authenticate: Basic realm="NETGEAR wnr2000', icase:TRUE)) {

  concl = chomp(concl);
  location = "/";
  version = "unknown";

  set_kb_item(name:"netgear_wnr2000/detected", value:TRUE);

  # CPE not available, building cpe name as cpe:/h:netgear:wnr2000
  cpe = "cpe:/h:netgear:wnr2000";

  register_product(cpe:cpe, location:location, port:port, service:"www");

  log_message(data:build_detection_report(app:"NETGEAR wnr2000 Router",
                                          version:version,
                                          install:location,
                                          cpe:cpe,
                                          concluded:concl),
                                          port:port);
  exit(0);
}
