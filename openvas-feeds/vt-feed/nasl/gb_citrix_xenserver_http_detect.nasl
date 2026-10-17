# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105763");
  script_version("2026-10-16T05:49:01+0000");
  script_tag(name:"last_modification", value:"2026-10-16 05:49:01 +0000 (Fri, 16 Oct 2026)");
  script_tag(name:"creation_date", value:"2016-06-14 12:25:04 +0200 (Tue, 14 Jun 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Citrix XenServer Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Citrix XenServer.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/";

res = http_get_cache(port: port, item: url);

if ((res !~ "<title>Welcome to (Citrix )?XenServer" && res !~ '<title>XenServer [0-9.]+</title>' ) ||
    ("Citrix Systems, Inc" >!< res && "Citrix Ocean" >!< res))
  exit( 0 );

set_kb_item(name: "citrix/xenserver/detected", value: TRUE);
set_kb_item(name: "citrix/xenserver/http/detected", value: TRUE);
set_kb_item(name: "citrix/xenserver/http/port", value: port);

version = "unknown";
location = "/";
conclUrl = "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

vers = eregmatch(pattern: "XenServer ([0-9.]+)", string: res);
if (!isnull(vers[1])) {
  version = vers[1];
  set_kb_item(name: "citrix/xenserver/http/" + port + "/concluded", value: vers[0]);
}

set_kb_item(name: "citrix/xenserver/http/" + port + "/version", value: version);
set_kb_item(name: "citrix/xenserver/http/" + port + "/concludedUrl", value: conclUrl);

exit(0);
