# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809066");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-10-18 11:30:44 +0530 (Tue, 18 Oct 2016)");

  script_name("AVTECH Device Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of AVTECH devices");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Avtech/banner");

  script_xref(name:"URL", value:"http://www.avtech.com.tw/");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if(!concl = egrep(string:banner, pattern:"Server:.*Avtech", icase:TRUE))
  exit(0);

version = "unknown";

set_kb_item(name:"avtech/detected", value:TRUE);

## Created new cpe
cpe = "cpe:/o:avtech:avtech_device_firmware";

os_register_and_report(os:"AVTECH Device Firmware", cpe:cpe, desc:"AVTECH Device Detection (HTTP)",
                       runs_key:"unixoide");

register_product(cpe:cpe, location:"/", port:port, service:"www");

log_message(data:build_detection_report(app:"AVTECH Device", version:version, install:"/", cpe:cpe,
                                        concluded:concl),
            port:port);

exit(0);
