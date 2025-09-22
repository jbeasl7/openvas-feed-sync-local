# SPDX-FileCopyrightText: 2005 David Maciejak
# SPDX-FileCopyrightText: New code/product registration code since 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17585");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("IBM Security SiteProtector (ISS) Deployment Manager Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 3994);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of the IBM Security SiteProtector (ISS)
  Deployment Manager.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:3994);

url = "/deploymentmanager/index.jsp";
res = http_get_cache(item:url, port:port);
if(!res || res !~ "^HTTP/1\.[01] 200")
  exit(0);

if("<title>SiteProtector</title>" >< res && "Welcome to SiteProtector Deployment Manager" >< res) {

  conclUrl = http_report_vuln_url(port:port, url:url, url_only:TRUE);
  version = "unknown";
  install = "/";
  cpe = "cpe:/a:ibm:security_siteprotector_system";

  set_kb_item(name:"ibm/security_siteprotector_system/detected", value:TRUE);
  set_kb_item(name:"ibm/security_siteprotector_system/http/detected", value:TRUE);

  register_product(cpe:cpe, location:install, port:port, service:"www");

  log_message(data:build_detection_report(app:"IBM Security SiteProtector (ISS) Deployment Manager",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concludedUrl:conclUrl),
              port:port);
}

exit(0);
