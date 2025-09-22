# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140385");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-09-21 14:31:53 +0700 (Thu, 21 Sep 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Kannel WAP/SMS Gateway Detection");

  script_tag(name:"summary", value:"Detection of Kannel WAP/SMS Gateway.

The script sends a connection request to the server and attempts to detect Kannel WAP/SMS Gateway and to extract
its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Kannel/banner");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://www.kannel.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");


port = http_get_port(default: 80);

banner = http_get_remote_headers(port: port);

if (egrep(pattern: "Kannel/", string: banner)) {
  version = "unknown";

  vers = eregmatch(pattern: "Server: Kannel/([0-9svnr.-]+)", string: banner);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "kannel/version", value: version);
  }

  set_kb_item(name: "kannel/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9svnr.-]+)", base: "cpe:/a:kannel:kannel:");
  if (!cpe)
    cpe = 'cpe:/a:kannel:kannel';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Kannel", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
