# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812657");
  script_version("2025-08-01T15:45:48+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-08-01 15:45:48 +0000 (Fri, 01 Aug 2025)");
  script_tag(name:"creation_date", value:"2018-01-22 12:19:43 +0530 (Mon, 22 Jan 2018)");
  script_name("Master IP Camera Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_thttpd_detect.nasl");
  script_mandatory_keys("thttpd/detected");

  script_tag(name:"summary", value:"HTTP based detection of Master IP Camera devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

# nb:
# - No get_app_location() as thttpd is only used within this product and there is no point
#   in linking to the detection of it
# - Also no need to use a "CPE" constant here
if(!port = get_app_port(cpe:"cpe:/a:acme:thttpd"))
  exit(0);

res = http_get_cache(item:"/web/index.html", port:port);

if(("<title>ipCAM<" >< res || "<title>Camera<" >< res) && "cgi-bin/hi3510" >< res && ">OCX" >< res) {

  version = "unknown";
  install = "/";
  set_kb_item(name:"MasterIP/Camera/Detected", value:TRUE);

  cpe = "cpe:/h:masterip:masterip_camera";

  register_product(cpe:cpe, location:install, port:port, service:"www");

  log_message(data:build_detection_report(app:"Master IP Camera",
                                          version:version,
                                          install:install,
                                          cpe:cpe),
              port:port);
}

exit(0);
