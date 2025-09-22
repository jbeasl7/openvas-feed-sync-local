# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811312");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-08-31 11:28:00 +0530 (Thu, 31 Aug 2017)");
  script_name("iBall Baton 150M Wireless Router Detection");

  script_tag(name:"summary", value:"Detection of iBall Baton 150M Wireless
  Router.

  The script sends a connection request to the server and attempts to
  detect the presence of iBall Baton 150M Wireless Router.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

netPort = http_get_port(default:80);
banner = http_get_remote_headers(port:netPort);

if(banner && 'WWW-Authenticate: Basic realm="iBall Baton 150M Wireless-N ADSL2+ Router' >< banner)
{
  location = "/";
  version = "Unknown";

  set_kb_item(name:"iBall_Baton_150M_Router/detected", value: TRUE);

  cpe = "cpe:/h:iball:baton_150m_wireless-n_router";

  register_product(cpe:cpe, location:location, port:netPort, service:"www");

  log_message(data: build_detection_report(app: "iBall Baton 150M Wireless Router",
                                           version: version,
                                           install: location,
                                           cpe: cpe,
                                           concluded: version),
                                           port: netPort);
  exit(0);
}
