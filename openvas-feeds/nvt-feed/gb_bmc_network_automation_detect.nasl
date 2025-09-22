# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141829");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2019-01-07 11:04:28 +0700 (Mon, 07 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("BMC Network Automation Detection");

  script_tag(name:"summary", value:"Detection of BMC Network Automation

The script sends a HTTP connection request to the server and attempts to detect BMC Network Automation and
to extract its version.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.bmc.com/it-solutions/truesight-network-automation.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

res = http_get_cache(port: port, item: "/bca-networks/main/displayTop.do");

if (res =~ "(BMC|TrueSight) Network Automation" && "powered by bmc" >< res) {
  version = "unknown";

  # <p>Version 8.9.04</p>
  vers = eregmatch(pattern: "<p>Version ([0-9.]+)</p>", string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "bmc_network_automation/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:bmc:network_automation:");
  if (!cpe)
    cpe = 'cpe:/a:bmc:network_automation';

  log_message(data: build_detection_report(app: "BMC Network Automation", version: version, install: "/",
                                           cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
