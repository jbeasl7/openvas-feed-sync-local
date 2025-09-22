# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114013");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-07-23 16:27:09 +0200 (Mon, 23 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Swarmpit UI Detection");

  script_tag(name:"summary", value:"Detection of Swarmpit Web UI.

  The script sends a connection request to the server and attempts to detect Swarmpit UI and to
  extract its version if possible.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8888);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://github.com/swarmpit/swarmpit");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8888);
url1 = "/version";
url2 = "/js/main.js";
res1 = http_get_cache(port: port, item: url1);
res2 = http_get_cache(port: port, item: url2);

# res1 example -> {"name":"swarmpit","version":"1.5","revision":"3ee51a8e6b96038fd47c0c306075f0ded16952ff","docker":{"api":1.37,"engine":"18.03.1-ce"}}
if('"name":"swarmpit"' >< res1 || "swarmpit.component.page-login" >< res2 || "swarmpit.component.mixin" >< res2) {
   version = "unknown";
   install = "/";

   vers = eregmatch(pattern: '"version":"([0-9.]+).*"', string: res1);
   conclUrl = http_report_vuln_url(port: port, url: url1, url_only: TRUE);

   if(vers[1]) version = vers[1];

   set_kb_item(name: "swarmpit/detected", value: TRUE);
   set_kb_item(name: "swarmpit/version", value: version);
   set_kb_item(name: "swarmpit/" + port + "/detected", value: TRUE);

   cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:swarmpit:swarmpit:"); # CPE is not registered yet

   if(!cpe) cpe = 'cpe:/a:swarmpit:swarmpit';

   register_product(cpe: cpe, location: install, port: port, service: "www");

   log_message(data: build_detection_report(app: "Swarmpit", version: version, install: install, cpe: cpe,
                                            concludedUrl: conclUrl),port: port);

}

exit(0);
