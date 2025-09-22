# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812758");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-02-08 17:51:20 +0530 (Thu, 08 Feb 2018)");
  script_name("Geovision Inc. IP Camera Remote Detection");

  script_tag(name:"summary", value:"Detection of running version of Geovision
  Inc. IP Camera.

  This script sends an HTTP GET request and tries to ensure the presence of
  Geovision Inc. IP Camera.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("cpe.inc");

port = http_get_port(default: 80);
url = "/ssi.cgi/Login.htm";

res = http_get_cache(port: port, item: "/ssi.cgi/Login.htm");

if('document.write("<INPUT name=umd5' >< res || 'document.write("<INPUT name=pmd5' >< res) {

  version = "unknown";

  set_kb_item(name: "geovision/ip_camera/detected", value: TRUE);

  CPE = "cpe:/h:geovision:geovisionip_camera";

  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  register_and_report_cpe(app: "GeoVision IP Camera",
                          ver: version,
                          concluded: version,
                          base: CPE,
                          expr: '([0-9.]+)',
                          insloc: "/",
                          regPort: port,
                          conclUrl: conclUrl);
}

exit(0);
