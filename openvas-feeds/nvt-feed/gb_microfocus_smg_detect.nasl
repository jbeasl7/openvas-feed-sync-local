# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141275");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-07-05 13:21:23 +0200 (Thu, 05 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Micro Focus Secure Messaging Gateway Detection");

  script_tag(name:"summary", value:"Detection of Micro Focus Secure Messaging Gateway.

The script sends a connection request to the server and attempts to detect Micro Focus Secure Messaging Gateway.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.microfocus.com/products/secure-gateway/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

res = http_get_cache(port: port, item: "/authenticate/login.php");

if ("<title>Secure Messaging Gateway Messaging Security</title>" >< res && "case 1600000004" >< res) {
  version = "unknown";

  set_kb_item(name: "microfocus_smg/installed", value: TRUE);

  cpe = 'cpe:/a:microfocus:secure_messaging_gateway';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Micro Focus Secure Messaging Gateway", version: version,
                                           install: "/", cpe: cpe),
              port: port);
  exit(0);
}

exit(0);
