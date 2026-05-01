# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140145");
  script_version("2026-04-28T06:28:06+0000");
  script_tag(name:"last_modification", value:"2026-04-28 06:28:06 +0000 (Tue, 28 Apr 2026)");
  script_tag(name:"creation_date", value:"2017-02-01 12:25:05 +0100 (Wed, 01 Feb 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dell PowerProtect Data Domain Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Dell PowerProtect Data Domain.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/";

res = http_get_cache(port: port, item: url);

if ("<title>PowerProtect DD System Manager</title>" >!< res ||
    "Redirecting to PowerProtect DD System Manager" >!< res) {
  url = "/ddem/login/";

  res = http_get_cache(port: port, item: url);

  if (("<title>DD System Manager</title>" >!< res && "<title>PowerProtect DD System Manager</title>" >!< res) &&
      ('companyName":"Data Domain"' >!< res || "DD System Manager Login" >!< res))
    exit(0);
}

version = "unknown";
model = "unknown";
conclUrl = "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

set_kb_item(name: "dell/powerprotect/data_domain/detected", value: TRUE);
set_kb_item(name: "dell/powerprotect/data_domain/http/detected", value: TRUE);
set_kb_item(name: "dell/powerprotect/data_domain/http/port", value: port);

# ,"appVersion":"6.0.0.9-544198",
vers = eregmatch(pattern: '"appVersion"\\s*:\\s*"([0-9.-]+)"', string: res);
if (!isnull(vers[1])) {
  version = vers[1];
  set_kb_item(name: "dell/powerprotect/data_domain/http/" + port + "/concluded", value: vers[0]);
}

set_kb_item(name: "dell/powerprotect/data_domain/http/" + port + "/version", value: version);
set_kb_item(name: "dell/powerprotect/data_domain/http/" + port + "/model", value: model);
set_kb_item(name: "dell/powerprotect/data_domain/http/" + port + "/concludedUrl", value: conclUrl);

exit(0);
