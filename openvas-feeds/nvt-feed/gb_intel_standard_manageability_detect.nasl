# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810998");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-05-05 15:39:37 +0530 (Fri, 05 May 2017)");

  script_name("Intel Standard Manageability (ISM) Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Intel Standard Manageability (ISM)");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 16992, 16993);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:16992);

res = http_get_cache(port:port, item: "/logon.htm");

# Intel(R) Standard Manageability 11.8.77.3664
if('Server: Intel(R) Standard Manageability' >< res &&
   '<title>Intel&reg; Standard Manageability</title>' >< res) {
  version = "unknown";

  ver = eregmatch(pattern:"Server: Intel\(R\) Standard Manageability ([0-9.]+)", string:res);
  if(!isnull(ver[1]))
    version = ver[1];

  set_kb_item(name:"intel/ism/detected", value:TRUE);

  cpe = build_cpe(value: version, exp:"^([0-9.]+)", base:"cpe:/o:intel:standard_manageability_firmware:");
  if(!cpe)
    cpe = "cpe:/o:intel:standard_manageability_firmware";

  os_register_and_report(os: "Intel Standard Manageability Firmware", cpe: cpe,
                         desc: "Intel Standard Manageability (ISM) Detection (HTTP)", runs_key: "unixoide");

  register_product(cpe:cpe, location:"/", port:port, service:"www");

  log_message(data:build_detection_report( app:"Intel Standard Manageability",
                                           version:version,
                                           install:"/",
                                           cpe:cpe,
                                           concluded:ver[0]),
                                           port:port);

}

exit(0);
