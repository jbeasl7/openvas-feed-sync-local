# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141092");
  script_version("2024-08-06T05:05:45+0000");
  script_tag(name:"last_modification", value:"2024-08-06 05:05:45 +0000 (Tue, 06 Aug 2024)");
  script_tag(name:"creation_date", value:"2018-05-16 12:08:03 +0700 (Wed, 16 May 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IBM Storwize / FlashSystem Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of IBM Storwize / FlashSystem.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/";

res = http_get_cache(port: port, item: url);

if ("- Log in -" >< res && 'poweredByStorwize' >< res && res =~ "IBM (Storwize|FlashSystem)") {
  version = "unknown";
  model = "unknown";
  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "ibm/storwize/detected", value: TRUE);
  set_kb_item(name: "ibm/storwize/http/detected", value: TRUE);
  set_kb_item(name: "ibm/storwize/http/port", value: port);

  mod = eregmatch(pattern: "IBM (Storwize|FlashSystem) (V?[0-9A-Z]+)", string: res);
  if (!isnull(mod[2])) {
    model = mod[2];
    set_kb_item(name: "ibm/storwize/http/" + port + "/concluded", value: mod[0]);
  }

  set_kb_item(name: "ibm/storwize/http/" + port + "/model", value: model);
  set_kb_item(name: "ibm/storwize/http/" + port + "/version", value: version);
  set_kb_item(name: "ibm/storwize/http/" + port + "/concludedUrl", value: conclUrl);
}

exit(0);
