# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801247");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-08-06 17:02:44 +0200 (Fri, 06 Aug 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Sun Java System Portal Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the running Sun Java System Portal Server version.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Sun Java System Portal Server Version Detection";

port = http_get_port(default:8080);

sndReq = http_get(item:"/psconsole/faces/common/ProductVersion.jsp", port:port);
rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

if(">Portal Server Product Version<" >< rcvRes && "Sun Microsystems" >< rcvRes)
{
  ver = eregmatch(pattern:">Version ([0-9.]+)<", string:rcvRes);

  if(ver[1] != NULL)
  {
    set_kb_item(name:"www/" + port + "/Sun/Java/Portal/Server", value:ver[1]);
    set_kb_item(name:"sun/java/portal/server/detected", value:TRUE);
    log_message(data:"Sun Java System Portal Server version " + ver[1] +
                       " was detected on the host", port:port);

    cpe = build_cpe(value:ver[1], exp:"^([0-9.]+)", base:"cpe:/a:sun:java_system_portal_server:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

  }
}
