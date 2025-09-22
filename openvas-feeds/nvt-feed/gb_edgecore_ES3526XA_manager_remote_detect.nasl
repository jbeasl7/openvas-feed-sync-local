# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808237");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-06-27 15:50:17 +0530 (Mon, 27 Jun 2016)");

  script_name("EdgeCore ES3526XA Manager Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of an EdgeCore ES3526XA Manager.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("SMC6128L2/banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if(!banner)
  exit(0);

#EdgeCore - Layer2+ Fast Ethernet Standalone Switch ES3526XA Manager
#Also rebranded as: *SMC TigerSwitch 10/100 SMC6128L2 Manager*
if(concl = egrep(string:banner, pattern:'WWW-Authenticate: Basic realm="SMC6128L2', icase:TRUE)) {

  version = "unknown";

  set_kb_item(name:"EdgeCore/ES3526XA/detected", value:TRUE);

  cpe = "cpe:/o:edgecore:es3526xa_firmware";

  os_register_and_report(os:"EdgeCore ES3526XA Firmware", cpe:cpe, desc:"EdgeCore ES3526XA Manager Detection (HTTP)", runs_key:"unixoide");

  register_product(cpe:cpe, location:"/", port:port, service:"www");

  log_message(data:build_detection_report(app:"EdgeCore ES3526XA Manager",
                                          version:version,
                                          install:"/",
                                          cpe:cpe,
                                          concluded:concl),
                                          port:port);
}

exit(0);
