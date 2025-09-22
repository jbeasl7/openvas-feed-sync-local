# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811877");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-10-24 17:24:40 +0530 (Tue, 24 Oct 2017)");
  script_name("Logitech SqueezeCenter/Media Server Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("LogitechMediaServer/banner");

  script_tag(name:"summary", value:"Detection of a Logitech SqueezeCenter/Media Server.

  This script sends a HTTP GET request to the target and try to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:9000);
banner = http_get_remote_headers(port:port);

if(_banner = egrep(string:banner, pattern:"^Server: Logitech Media Server", icase:TRUE)) {

  _banner = chomp(_banner);

  version = "unknown";

  # Server: Logitech Media Server (7.7.2 - 33893)
  ver = eregmatch(pattern:'Server: Logitech Media Server \\(([0-9.]+)[^)]*\\)', string:_banner);
  if(ver[1])
    version = ver[1];

  set_kb_item(name:"logitech/squeezecenter/detected", value:TRUE);
  set_kb_item(name:"logitech/squeezecenter/http/detected", value:TRUE);
  set_kb_item(name:"logitech/squeezecenter/http/port", value:port );
  set_kb_item(name:"logitech/squeezecenter/http/" + port + "/detected", value:TRUE);
  set_kb_item(name:"logitech/squeezecenter/http/" + port + "/version", value:version);
  set_kb_item(name:"logitech/squeezecenter/http/" + port + "/concluded", value:_banner);
}

exit(0);
