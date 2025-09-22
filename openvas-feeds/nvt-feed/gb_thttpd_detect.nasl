# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140800");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-02-23 10:46:04 +0700 (Fri, 23 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("thttpd Detection");

  script_tag(name:"summary", value:"Detection of thttpd.

  The script sends a connection request to the server and attempts to detect thttpd and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("thttpd/banner");

  script_xref(name:"URL", value:"https://acme.com/software/thttpd/");

  exit(0);
}

CPE = "cpe:/a:acme:thttpd:";

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

banner = http_get_remote_headers(port: port);
if ("Server: thttpd/" >!< banner)
  exit(0);

version = "unknown";

vers = eregmatch(pattern: "thttpd/([0-9a-z.]+)", string: banner);
if (!isnull(vers[1]))
  version = vers[1];

set_kb_item(name: "thttpd/detected", value: TRUE);

register_and_report_cpe(app: "thttpd",
                        ver: version,
                        concluded: vers[0],
                        base: CPE,
                        expr: "([0-9a-z.]+)",
                        insloc: port + "/tcp",
                        regPort: port,
                        regService: "www" );

exit(0);
