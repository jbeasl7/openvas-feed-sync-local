# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106178");
  script_version("2022-05-10T12:04:11+0000");
  script_tag(name:"last_modification", value:"2022-05-10 12:04:11 +0000 (Tue, 10 May 2022)");
  script_tag(name:"creation_date", value:"2016-10-10 12:16:07 +0700 (Mon, 10 Oct 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WSO2 Carbon Products Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of WSO2 Carbon products.");

  script_tag(name:"insight", value:"The following products are currently known to be
  covered/detected:

  - WSO2 Identity Server

  - WSO2 Enterprise Service Bus

  - WSO2 Data Analytics Server

  - WSO2 API Manager

  - WSO2 Complex Event Processor

  - WSO2 Governance Registry

  - WSO2 Business Process Server

  - WSO2 Storage Server

  - WSO2 Enterprise Integrator");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://wso2.com/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 9443);

banner = http_get_remote_headers(port: port);

url = "/carbon/product/about.html";
res = http_get_cache(item: url, port: port);

product = "unknown";

# Server: WSO2 Carbon Server
# server: WSO2 Carbon Server
if (concl = egrep(string: banner, pattern: "^[Ss]erver\s*:\s*WSO2 Carbon Server", icase: FALSE)) {
  found = TRUE;
  concluded = "  " + chomp(concl);
}

# <head><title>WSO2 Identity Server - About</title>
# <head><title>WSO2 API Manager - About</title>
# <html><head><title>WSO2 EI - About</title>
# <html><head><title>WSO2 Governance Registry - About</title>
# <head><title>WSO2 Data Analytics Server  - About</title>
#
# nb: Currently unclear if we should include a detection for the AS in this detection:
# <title>WSO2 AS 5.3.0 (Apache Tomcat 7.0.82/TomEE 1.7.2) - Error report</title>
#
if (concl = eregmatch(string: res, pattern: "<title>WSO2 [^<]+</title>", icase: FALSE)) {

  if (concluded)
    concluded += '\n';
  concluded += "  " + concl[0];

  # <h2><a href="http://wso2.org/library/identity-server">About WSO2 Identity Server</a></h2>
  # <h2>About WSO2 API Manager</h2>
  # <h2>About WSO2 Governance Registry</h2>
  # nb: Trailing space after the following products were seen like this "live":
  # <h2>About WSO2 EI </h2>
  # <h2>About WSO2 Data Analytics Server </h2>
  prod = eregmatch(string: res, pattern: "About WSO2 ([^<]+)", icase: FALSE);
  if (prod[1]) {
    found = TRUE;
    product = chomp(prod[1]);
    if (concluded)
      concluded += '\n';
    concluded += "  " + prod[0];
  }
}

if (found) {

  if (product == "Identity Server") {
    kb_name = "wso2_carbon_identity_server";
    cpe = "cpe:/a:wso2:identity_server";
    app = "WSO2 Identity Server";
  }

  else if (product == "ESB") {
    kb_name = "wso2_carbon_enterprise_service_bus";
    cpe = "cpe:/a:wso2:enterprise_service_bus";
    app = "WSO2 Enterprise Service Bus";
  }

  else if (product == "Data Analytics Server") {
    kb_name = "wso2_carbon_data_analytics_server";
    cpe = "cpe:/a:wso2:data_analytics_server";
    app = "WSO2 Data Analytics Server";
  }

  else if (product == "API Manager") {
    kb_name = "wso2_carbon_api_manager";
    cpe = "cpe:/a:wso2:api_manager";
    app = "WSO2 API Manager";
  }

  else if (product == "Complex Event Processor") {
    kb_name = "wso2_carbon_complex_event_processor";
    cpe = "cpe:/a:wso2:complex_event_processor";
    app = "WSO2 Complex Event Processor";
  }

  else if (product == "Governance Registry") {
    kb_name = "wso2_carbon_governance_registry";
    cpe = "cpe:/a:wso2:governance_registry";
    app = "WSO2 Governance Registry";
  }

  else if (product == "Business Process Server") {
    kb_name = "wso2_carbon_business_process_server";
    cpe = "cpe:/a:wso2:business_process_server";
    app = "WSO2 Business Process Server";
  }

  else if (product == "Storage Server") {
    kb_name = "wso2_carbon_storage_server";
    cpe = "cpe:/a:wso2:storage_server";
    app = "WSO2 Storage Server";
  }

  else if (product == "EI") {
    kb_name = "wso2_carbon_enterprise_integrator";
    cpe = "cpe:/a:wso2:enterprise_integrator";
    app = "WSO2 Enterprise Integrator";
  }

  # TODO: Some carbon based servers are not identifiable through this method.
  else {
    kb_name = "wso2_carbon_unknown_product";
    cpe = "cpe:/a:wso2:unknown_product";
    app = "WSO2 Unknown Product";
  }

  set_kb_item(name: kb_name + "/detected", value: TRUE);
  set_kb_item(name: "wso2/carbon/detected", value: TRUE);
  set_kb_item(name: "wso2/carbon/http/detected", value: TRUE);

  concl_url = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  version = "unknown";

  # <h1>Version 4.0.0</h1>
  # <h1>Version 6.4.0</h1>
  # <h1>Version 1.9.0</h1>
  # <h1>Version 2.1.0</h1>
  # <h1>Version 5.4.0</h1>
  # <h1>Version 2.5.0</h1>
  # <h1>Version 3.1.0</h1>
  vers = eregmatch(pattern: "<h1>Version ([0-9.]+)", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    cpe = cpe + ":" + version;
    concluded += '\n  ' + vers[0];
  }

  else if (product == "Storage Server") {
    vers = eregmatch(pattern: "Storage Server Version ([0-9.]+)", string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      cpe = cpe + ":" + version;
      concluded += '\n  ' + vers[0];
    }
  }

  register_product(cpe: cpe, location: "/carbon", port: port, service: "www");

  log_message(data: build_detection_report(app: app, version: version, install: "/carbon", cpe: cpe,
                                           concluded: concluded, concludedUrl: concl_url),
              port: port);

  exit(0);
}

exit(0);
