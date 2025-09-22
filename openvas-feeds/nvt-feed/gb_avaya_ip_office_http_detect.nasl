# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106322");
  script_version("2024-10-09T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-10-09 05:05:35 +0000 (Wed, 09 Oct 2024)");
  script_tag(name:"creation_date", value:"2016-10-04 13:39:10 +0700 (Tue, 04 Oct 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Avaya IP Office Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Avaya IP Office.");

  script_xref(name:"URL", value:"https://www.avaya.com/en/products/ip-office/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/index.html";

res = http_get_cache(port: port, item: url);

if ("<title>About IP Office" >< res && "<o:Company>Avaya</o:Company>" >< res) {
  version = "unknown";
  location = "/";
  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  vers = eregmatch(pattern: "Version: ([0-9.]+) \(([0-9]+)\)", string: res);
  if(!isnull(vers[1]) && !isnull(vers[2])) {
    version = vers[1] + '.' + vers[2];
  } else {
    # >IP Office R11.0.4.1<
    # >IP Office Select R10.0.0.3<
    # >IP Office Application Server - Linux PC R11.1.2.0<
    vers = eregmatch(pattern: ">IP\s+Office [^R]*R([0-9.]+)<", string: res, icase: FALSE);
    if (!isnull(vers[1]))
      version = vers[1];
  }

  set_kb_item(name: "avaya/ip_office/detected", value: TRUE);
  set_kb_item(name: "avaya/ip_office/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:avaya:ip_office:");
  if (!cpe)
    cpe = "cpe:/a:avaya:ip_office";

  register_product(cpe: cpe, location: location, port: port, service: "www");

  if (">IP Office Application Server" >< res) {
    set_kb_item(name: "avaya/ip_office/application_server/detected", value: TRUE);
    set_kb_item(name: "avaya/ip_office/application_server/http/detected", value: TRUE);

    cpe2 = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:avaya:ip_office_application_server:");
    if (!cpe2)
      cpe2 = "cpe:/a:avaya:ip_office_application_server";

    register_product(cpe: cpe2, location: location, port: port, service: "www");

    extra = "  - Additional CPE registered: " + cpe2;
  }

  if (">IP Office Select" >< res) {
    set_kb_item(name: "avaya/ip_office/select/detected", value: TRUE);
    set_kb_item(name: "avaya/ip_office/select/http/detected", value: TRUE);

    cpe2 = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:avaya:ip_office_select:");
    if (!cpe2)
      cpe2 = "cpe:/a:avaya:ip_office_select";

    register_product(cpe: cpe2, location: location, port: port, service: "www");

    if (extra)
      extra += '\n';
    extra += "  - Additional CPE registered: " + cpe2;
  }

  log_message(data: build_detection_report(app: "Avaya IP Office", version: version,
                                           install: location, cpe: cpe, concluded: vers[0],
                                           concludedUrl: conclUrl, extra: extra),
              port: port);
  exit(0);
}

exit(0);
