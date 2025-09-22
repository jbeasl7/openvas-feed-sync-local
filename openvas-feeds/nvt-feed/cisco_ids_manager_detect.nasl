# SPDX-FileCopyrightText: 2009 LSS
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102006");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2009-06-23 09:27:52 +0200 (Tue, 23 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("CISCO IDS Manager Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 LSS");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects if CISCO IDS Manager is running on a given host and port.

  The IDS Device Manager is a web-based Java application that resides
  on the sensor and is accessed via a secure, encrypted TLS link using
  standard Netscape and Internet Explorer web browsers to perform
  various management and monitoring tasks.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:443);
body = http_get_cache(item:"/", port:port);

if("<title>Cisco Systems IDS Device Manager</title>" >< body) {

  set_kb_item(name:"cisco/ids_manager/detected", value:TRUE);

  # CPE is currently not registered
  cpe = "cpe:/a:cisco:ids_device_manager";

  register_product(cpe:cpe, location:port + "/tcp", port:port, service:"www");

  log_message(data:build_detection_report(app:"Cisco IDS Device Manager",
                                          install:port + "/tcp",
                                          cpe:cpe),
              port:port );
}

exit(0);
