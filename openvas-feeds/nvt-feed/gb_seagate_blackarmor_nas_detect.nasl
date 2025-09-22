# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103753");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2013-08-08 17:20:17 +0200 (Thu, 08 Aug 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Seagate BlackArmor NAS Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Seagate BlackArmor NAS devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.seagate.com/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

res = http_get_cache(port: port, item: "/index.php");

if (("<title>Seagate NAS" >!< res || "p_user" >!< res) && "Login to BlackArmor" >!< res)
  exit(0);

model = "unknown";
version = "unknown";
install = "/";

set_kb_item(name: "seagate/blackarmor_nas/detected", value: TRUE);
set_kb_item(name: "seagate/blackarmor_nas/http/detected", value: TRUE);

# <title>Seagate NAS - NAS-220</title>
mod = eregmatch(pattern: "Seagate NAS - ([0-9A-Z-]+)", string: res);
if (!isnull(mod[1]))
  model = mod[1];

os_name = "Seagate BlackArmor NAS ";
hw_name = os_name;

if (model != "unknown") {
  os_name += model + " Firmware";
  hw_name += model;

  cpe_model = tolower(str_replace(string: model, find: "-", replace: "_"));

  os_cpe = "cpe:/o:seagate:blackarmor_" + cpe_model + "_firmware";
  hw_cpe = "cpe:/h:seagate:blackarmor_" + cpe_model;
} else {
  os_name += "Firmware";
  hw_name += "Unknown Model";

  os_cpe = "cpe:/o:seagate:blackarmor_nas_firmware";
  hw_cpe = "cpe:/h:seagate:blackarmor_nas";
}

os_register_and_report(os: os_name, cpe: os_cpe,
                       desc: "Seagate BlackArmor NAS Detection (HTTP)", runs_key: "unixoide");

register_product(cpe: os_cpe, location: "/", port: port, service: "www");
register_product(cpe: hw_cpe, location: "/", port: port, service: "www");

report =  build_detection_report(app: os_name, version: version, install: install,
                                 cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: install,
                                 cpe: hw_cpe);

log_message(port: port, data: report);

exit(0);
