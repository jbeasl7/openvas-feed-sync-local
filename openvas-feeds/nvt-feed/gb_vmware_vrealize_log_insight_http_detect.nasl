# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105753");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2016-06-10 12:33:05 +0200 (Fri, 10 Jun 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("VMware vRealize Log Insight / VMware Aria Operations for Logs Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of VMware vRealize Log Insight or VMware
  Aria Operations for Logs.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/login";

res = http_get_cache(port: port, item: url);

if ("<title>vRealize Log Insight - Login</title>" >!< res &&
    # <title>Operations for Logs - Login | </title>
    # nb: As it isn't clear if the there could be some optional text behind the "|" it has been made
    # optional in the regex below.
    res !~ "<title>Operations for Logs - Login[^<]*</title>" &&
    #                <span class="app-name-container">
    #                    VMware Aria Operations<div class="trademark-container">
    #                        <span class="trademark">&#8482;</span>
    #                    </div>
    #                    for Logs</span>
    #                <div>
    #
    # or:
    #
    #                <span class="app-name-container">
    #                    VMware Aria Operations
    #                    <div class="trademark-container">
    #                        <span class="trademark">&#8482;</span>
    #                    </div>
    #                    for Logs
    #                </span>
    #                <div>
    res !~ 'VMware Aria Operations\\s*<div class="trademark-container">.+for Logs\\s*</span>')
  exit(0);

version = "unknown";
build = "unknown";
concUrl = "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

set_kb_item(name: "vmware/vrealize_log_insight/detected", value: TRUE);
set_kb_item(name: "vmware/vrealize_log_insight/http/detected", value: TRUE);
set_kb_item(name: "vmware/vrealize_log_insight/http/port", value: port);

# Note: Newer versions (at least 8.x) need authentication
url = "/api/v1/version";
res = http_get_cache(port: port, item: url);

# {"releaseName":"GA","version":"4.0.0-4624504"}
if ('"releaseName"' >< res) {
  vers = eregmatch(pattern: '"version":"([0-9.]+)-([0-9]+)"', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    set_kb_item(name: "vmware/vrealize_log_insight/http/" + port + "/concluded", value: vers[0]);
  }

  if (!isnull(vers[2]))
    build = vers[2];
}

set_kb_item(name: "vmware/vrealize_log_insight/http/" + port + "/version", value: version);
set_kb_item(name: "vmware/vrealize_log_insight/http/" + port + "/build", value: build);
set_kb_item(name: "vmware/vrealize_log_insight/http/" + port + "/concludedUrl", value: concUrl);

exit(0);
