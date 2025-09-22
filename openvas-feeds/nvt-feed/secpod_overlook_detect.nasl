# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902513");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2011-05-09 15:38:03 +0200 (Mon, 09 May 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("OPEN IT OverLook Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends an HTTP GET request to figure out whether OverLook is running on the remote host, and, if so, which version is installed.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

foreach dir (make_list("/overlook"))
{
  install = dir;
  if (dir == "/") dir = "";

  sndReq = http_get(item:string(dir, "/src/login.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  if(">OverLook by Open IT<" >< rcvRes)
  {
    set_kb_item(name:"overlook/detected", value:TRUE);
    version = "unknown";
    version_url = dir + "/README";

    sndReq = http_get(item:version_url, port:port);
    rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

    ver_match = eregmatch(pattern:"Version \.+ ([0-9.]+)", string:rcvRes);
    if(ver_match[1])
    {
      version = ver_match[1];
      concluded_url = http_report_vuln_url(port:port, url:version_url, url_only:TRUE);
    }

    register_and_report_cpe(app:"OverLook", ver:version, concluded:ver_match[0], base:"cpe:/a:openit:overlook:", expr:"^([0-9.]+)", insloc:install, regPort:port, conclUrl:concluded_url);

    exit(0);
  }
}
