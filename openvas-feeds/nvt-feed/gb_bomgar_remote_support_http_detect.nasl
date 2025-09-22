# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805199");
  script_version("2024-07-03T06:48:05+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-07-03 06:48:05 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"creation_date", value:"2015-06-22 16:44:50 +0530 (Mon, 22 Jun 2015)");

  script_name("Bomgar Remote Support Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Bomgar Remote Support.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  # nb: To avoid duplicate reporting because the VT below is also covering this product in a more
  # advanced way.
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_beyondtrust_remote_support_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning", "bomgar/remote_support/http/detected");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

# nb: See note above
if(get_kb_item("bomgar/remote_support/http/detected"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:80);

# nb: Only installed on the root dir...
url = "/";
res = http_get_cache(item:url, port:port);
if(!res || res !~ "^HTTP/1\.[01] 200" || "Bomgar Corporation" >!< res || "Support Portal" >!< res)
  exit(0);

version = "unknown";

# <!--Product Version: 14.3.1-->
# <!--Product Version: 14.2.3-->
# <!--Product Version: 14.3.3fips-->
# <!--Product Version: 13.1.2-->
#
# nb: Only products from around 2014-2015 and prior are exposing the version.
#
vers = eregmatch(pattern:"<!--Product Version: ([0-9.]+)", string:res);
if(vers[1])
  version = vers[1];

set_kb_item(name:"bomgar/remote_support/detected", value:TRUE);
set_kb_item(name:"bomgar/remote_support/http/detected", value:TRUE);

cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:bomgar:remote_support:");
if(!cpe)
  cpe = "cpe:/a:bomgar:remote_support";

register_product(cpe:cpe, location:url, port:port, service:"www");
log_message(data:build_detection_report(app:"Bomgar Remote Support",
                                        version:version,
                                        install:url,
                                        cpe:cpe,
                                        concluded:vers[0]),
            port:port);

exit(0);
