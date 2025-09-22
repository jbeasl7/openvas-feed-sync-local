# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902258");
  script_version("2025-03-21T05:38:29+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-21 05:38:29 +0000 (Fri, 21 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-10-01 08:36:34 +0200 (Fri, 01 Oct 2010)");
  script_name("SmarterMail Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of SmarterMail.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 9998);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:9998);
if(!http_can_host_asp(port:port))
  exit(0);

res = http_get_cache(item:"/Login.aspx", port:port);

if(">SmarterMail" >!< res && ">SmarterMail Enterprise" >!< res && ">SmarterMail Standard" >!< res)
  exit(0);

version = "unknown";
install = "/";

ver = eregmatch(pattern:">SmarterMail [a-zA-Z]+ ([0-9.]+)<", string:res);
if(ver[1])
  version = ver[1];

set_kb_item(name:"SmarterMail/Ver", value:version);
set_kb_item(name:"SmarterMail/installed", value:TRUE);

# nb: All VTs using the above should be updated to use these in the future
set_kb_item(name:"smartermail/detected", value:TRUE);
set_kb_item(name:"smartermail/http/detected", value:TRUE);

cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:smartertools:smartermail:");
if(!cpe)
  cpe = "cpe:/a:smartertools:smartermail";

register_product(cpe:cpe, location:install, port:port, service:"www");
log_message(data:build_detection_report(app:"SmarterMail",
                                        version:version,
                                        install:install,
                                        cpe:cpe,
                                        concluded:ver[0]),
            port:port);

exit(0);
