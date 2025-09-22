# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113557");
  script_version("2025-01-30T05:38:01+0000");
  script_tag(name:"last_modification", value:"2025-01-30 05:38:01 +0000 (Thu, 30 Jan 2025)");
  script_tag(name:"creation_date", value:"2019-11-08 15:48:22 +0200 (Fri, 08 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Forcepoint Email Security Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Forcepoint Email Security.");

  script_xref(name:"URL", value:"https://www.forcepoint.com/product/email-data-loss-prevention-dlp");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

host = http_host_name(dont_add_port: TRUE);

url = "/pem/login/pages/login.jsf";

res = http_get_cache(port: port, item: url);

if ("<title>Forcepoint Email Security" >!< res || "var idPwd" >!< res) {
  url = "/pemserver/login/pages/login.jsf";

  res = http_get_cache(port: port, item: url);

  if ("<title>Forcepoint Email Security" >!< res || "var idPwd" >!< res)
    exit(0);
}

version = "unknown";
location = "/";
conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

set_kb_item(name: "forcepoint/email_security/detected", value: TRUE);
set_kb_item(name: "forcepoint/email_security/http/detected", value: TRUE);

# nb: For JavaServer Faces active checks (See "login.jsf" above)
set_kb_item(name: "www/javaserver_faces/detected", value: TRUE);
set_kb_item(name: "www/javaserver_faces/" + host + "/" + port + "/detected", value: TRUE);

# <div id="versionClass"> &nbsp;Version&nbsp;8.5.3 </div>
vers = eregmatch(pattern: "&nbsp;Version&nbsp;([0-9.]+)", string: res);
if (!isnull(vers[1]))
  version = vers[1];

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:forcepoint:email_security:");
if (!cpe)
  cpe = "cpe:/a:forcepoint:email_security";

register_product(cpe: cpe, location: location, port: port, service: "www");

log_message(data: build_detection_report(app: "Forcepoint Email Security", version: version,
                                         install: location, cpe: cpe, concluded: vers[0],
                                         concludedUrl: conclUrl),
            port: port);
exit(0);
