# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809334");
  script_version("2024-06-21T15:40:03+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-21 15:40:03 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"creation_date", value:"2016-10-06 14:17:14 +0530 (Thu, 06 Oct 2016)");

  script_name("ZKTeco ZKBioSecurity Detection (HTTP)");
  script_tag(name:"summary", value:"HTTP based detection of ZKTeco ZKBioSecurity.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8088);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.zktecousa.com/product-page/all-in-one-management-software-for-access-control-zkbiosecurity");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default:8088);

res = http_get_cache(item:"/", port:port);

if("<title>ZKBioSecurity</title>" >< res && "password" >< res){
  install = "/";
  version = "unknown";
  app = "ZKteco ZKBioSecurity";
  url = "/baseLicense.do";
  data = "getLicenseInfo=";

  headers = make_array("Content-Type", "application/x-www-form-urlencoded;",
                       "X-Requested-With", "XMLHttpRequest");

  req = http_post_put_req(port: port, url: url, data: data, add_headers: headers, referer_url: "/");
  res = http_keepalive_send_recv(port: port, data: req);

  set_kb_item(name:"ZKTeco/ZKBioSecurity/detected", value:TRUE);

  # showAuthLicensePopup(this)" >
  #    <a href="javascript:void(0)">4.1.1_R&nbsp;Detalles<
  match = eregmatch(pattern: 'showAuthLicensePopup\\(this\\)"\\s*>[^>]+>([0-9.]+)[^<]*<', string: res);

  if (!isnull(match[1])) {
    version = match[1];
    conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:zkteco:zkbiosecurity:");
  if (!cpe)
    cpe = "cpe:/a:zkteco:zkbiosecurity";

  os_register_and_report(os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", port: port,
                         desc: "ZKteco ZKBioSecurity Detection (HTTP)", runs_key: "windows");

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: app, version: version, install: install,
                                           cpe: cpe, concluded: match[0], concludedUrl: conclUrl),
              port: port);

}

exit(0);