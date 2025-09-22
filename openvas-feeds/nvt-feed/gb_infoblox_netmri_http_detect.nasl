# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103575");
  script_version("2025-06-09T05:41:14+0000");
  script_tag(name:"last_modification", value:"2025-06-09 05:41:14 +0000 (Mon, 09 Jun 2025)");
  script_tag(name:"creation_date", value:"2012-09-25 12:05:19 +0200 (Tue, 25 Sep 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Infoblox NetMRI Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Infoblox NetMRI.");

  script_add_preference(name:"Infoblox NetMRI Web UI Username", value:"", type:"entry", id:1);
  script_add_preference(name:"Infoblox NetMRI Web UI Password", value:"", type:"password", id:2);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/netmri/config/userAdmin/login.tdf";

data = "mode=LOGIN-FORM";

req = http_post(port: port, item: url, data: data);
res = http_keepalive_send_recv(port: port, data: req);

if ("<title>NetMRI Login" >< res || "<title>Network Automation Login" >< res ||
    "Infoblox NetMRI Appliance" >< res) {
  version = "unknown";
  conclUrl = "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "infoblox/netmri/detected", value: TRUE);
  set_kb_item(name: "infoblox/netmri/http/detected", value: TRUE);
  set_kb_item(name: "infoblox/netmri/http/port", value: port);

  # This probably could be checked with a single eregmatch(), however the correct regex is unclear
  lines = split(res);
  c = 0;

  foreach line(lines) {
    c++;
    if ("Version:" >< line) {
       vers = eregmatch(pattern: "<td>([^<]+)</td>", string: lines[c]);
       if (!isnull(vers[1])) {
         version = vers[1];
         set_kb_item(name: "infoblox/netmri/http/" + port + "/concluded", value: vers[0]);
         break;
       }
    }
  }

  if (version == "unknown") {
    user = script_get_preference("Infoblox NetMRI Web UI Username", id: 1);
    pass = script_get_preference("Infoblox NetMRI Web UI Password", id: 2);

    if (!user && !pass) {
      set_kb_item(name: "infoblox/netmri/http/" + port + "/error",
                  value: "  Note: No username and password for web authentication were provided. These could be provided for extended version extraction.");
    } else if (!user && pass) {
      set_kb_item(name: "infoblox/netmri/http/" + port + "/error",
                  value: "  Note: Password for web authentication was provided but username is missing. Please provide both.");
    } else if (user && !pass) {
      set_kb_item(name: "infoblox/netmri/http/" + port + "/error",
                  value: "  Note: Username for web authentication was provided but password is missing. Please provide both.");
    } else if (user && pass) {
      url = "/api/server_info.json";

      headers = make_array("Authorization", "Basic " + base64(str: user + ":" + pass));

      req = http_get_req(port: port, url: url, add_headers: headers);
      res = http_keepalive_send_recv(port: port, data: req);

      vers = eregmatch(pattern: '"netmri_version"\\s*:\\s*"([0-9.]+)"', string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        set_kb_item(name: "infoblox/netmri/http/" + port + "/concluded", value: vers[0]);
        conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      } else {
        set_kb_item(name: "infoblox/netmri/http/" + port + "/error",
                    value: "  Note: Username and password were provided but authentication failed.");
      }
    }
  }

  set_kb_item(name: "infoblox/netmri/http/" + port + "/version", value: version);
  set_kb_item(name: "infoblox/netmri/http/" + port + "/concludedUrl", value: conclUrl);
}

exit(0);
