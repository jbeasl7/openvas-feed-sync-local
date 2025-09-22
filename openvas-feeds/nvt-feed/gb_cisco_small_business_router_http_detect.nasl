# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141918");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2019-01-25 09:35:38 +0700 (Fri, 25 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco Small Business Router Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of Cisco Small Business Routers.

The script sends a HTTP(S) connection request to the server and attempts to detect Cisco Small Business Routers.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/solutions/small-business/routers.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

res = http_get_cache(port: port, item: "/");

if ("<title>Router</title>" >< res && "trademarks of Cisco Systems" >< res &&
    'getElementById("nk_login")' >< res) {
  version = "unknown";

  set_kb_item(name: "cisco/smb_router/detected", value: TRUE);
  set_kb_item(name: "cisco/smb_router/http/port", value: port);

  # This is just a detection of the web interface without any model/version detection
  # therefore no product/cpe registration
  log_message(data: build_detection_report(app: "Cisco Small Business Router", version: version, install: "/"),
              port: port);
  exit(0);
}

exit(0);
