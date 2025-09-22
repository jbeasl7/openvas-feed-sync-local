# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114009");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-07-16 15:22:55 +0200 (Mon, 16 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Kubernetes Dashboard UI Detection");

  script_tag(name:"summary", value:"Detection of Kubernetes Dashboard/Web UI.

  The script sends a connection request to the server and attempts to detect Kubernetes Dashboard UI and to
  extract its version if possible.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://github.com/kubernetes/dashboard");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);
res1 = http_get_cache(port: port, item: "/");
res2 = http_get_cache(port: port, item: "/api/v1/overview");

# ng-app="kubernetesDashboard">
if(egrep(pattern: "[Kk]ubernetesDashboard", string: res1) ||
    "system:serviceaccount:kube-system:kubernetes-dashboard" >< res2) {
   version = "unknown";
   install = "/";

   id = eregmatch(pattern: 'src="static/app\\.([^.]+)\\.js">', string: res1);

   if(id[1]){
      url = "/static/app." + id[1] + ".js";
      conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

      res3 = http_get_cache(port: port, item: url);
      vers = eregmatch(pattern: 'dashboardVersion="v([0-9.]+)"', string: res3);

      if(vers[1]) version = vers[1];
   }

   set_kb_item(name: "kubernetes/dashboard/detected", value: TRUE);
   set_kb_item(name: "kubernetes/dashboard/version", value: version);
   set_kb_item(name: "kubernetes/dashboard/" + port + "/detected", value: TRUE);

   cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:kubernetes:dashboard:"); # CPE is not registered yet

   if(!cpe) cpe = 'cpe:/a:kubernetes:dashboard';

   register_product(cpe: cpe, location: install, port: port, service: "www");

   log_message(data: build_detection_report(app: "Kubernetes Dashboard", version: version, install: install, cpe: cpe,
                                            concluded: vers[0], concludedUrl: conclUrl),port: port);

}

exit(0);
