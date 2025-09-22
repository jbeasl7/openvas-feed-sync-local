# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140388");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-09-22 11:50:19 +0700 (Fri, 22 Sep 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Saia Burgess Controls (SBC) PCD Detection");

  script_tag(name:"summary", value:"Detection of Saia Burgess Controls (SBC) PCD devices.

The script sends a connection request to the server and attempts to detect SBC PCD devices and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Saia_PCD/banner");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://www.sbc-support.com/en/product-category/programmable-controller/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

banner = http_get_remote_headers(port: port);

if ("Server: Saia PCD" >< banner) {
  version = "unknown";

  vers = eregmatch(pattern: 'Saia ([^/]+)/([0-9.]+)', string: banner);
  if (isnull(vers[1]))
    exit(0);
  else {
    model = vers[1];
    set_kb_item(name: "saia_pcd/model", value: model);
  }

  if (!isnull(vers[2])) {
    version = vers[2];
    set_kb_item(name: "saia_pcd/version", value: version);
  }

  set_kb_item(name: "saia_pcd/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/h:saia_burgess_controls:" + tolower(model) + ":");
  if (!cpe)
    cpe = 'cpe:/h:saia_burgess_controls:' + tolower(model);

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "SBC PCD " + model, version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
