# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106086");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-05-26 11:12:13 +0700 (Thu, 26 May 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Linknat VOS SoftSwitch Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Linknat VOS SoftSwitch.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");


  script_xref(name:"URL", value:"http://www.linknat.com");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/eng/js/lang_en_us.js";
res = http_get_cache(item: url, port: port);

if ("Welcome to Web Self-Service System" >< res && "GatewayPasswordModification" >< res) {
  model = "unknown";
  mo = eregmatch(pattern: 's\\[8\\] = \\"(VOS[0-9]{4})', string: res);
  if (!isnull(mo[1]))
    model = mo[1];

  version = "unknown";
  ver = eregmatch(pattern: 'Version: ([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)', string: res);
  if (!isnull(ver[1]))
    version = ver[1];

  set_kb_item(name: "linknat_vos/detected", value: TRUE);
  set_kb_item(name: "linknat_vos/http/port", value: port);

  if (model != "unknown")
    set_kb_item(name: "linknat_vos/http/model", value: model);

  if (version != "unknown")
    set_kb_item(name: "linknat_vos/http/version", value: version);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:linknat:vos:" + tolower(model) + ":");
  if (isnull(cpe)) {
    if (model != "unknown")
      cpe = "cpe:/a:linknat:vos:" + model;
    else
      cpe = "cpe:/a:linknat:vos";
  }

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Linknat SoftSwitch " + model,
                                           version: version,
                                           install: "/",
                                           cpe: cpe, concluded: ver[0]),
              port: port);
}

exit(0);

