# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103418");
  script_version("2023-06-29T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-29 05:05:23 +0000 (Thu, 29 Jun 2023)");
  script_tag(name:"creation_date", value:"2012-02-14 11:30:38 +0100 (Tue, 14 Feb 2012)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("VMware ESX / ESXi Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of VMware ESX / ESXi.");

  script_xref(name:"URL", value:"http://www.vmware.com");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

SCRIPT_DESC = "VMware ESX / ESXi Detection (HTTP)";

port = http_get_port(default:443);
host = http_host_name(port:port);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

req  = string("GET / HTTP/1.1\r\n");
req += string("Host: ", host, "\r\n\r\n");

send(socket:soc, data:req);
buf = recv(socket:soc, length:8192);
close(soc);

if("VMware ESX" >!< buf && "ID_EESX_Welcome" >!< buf) {
  url = "/ui/";
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if("esxUiApp" >!< buf || "root.title" >!< buf)
    exit(0);
}

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

vers = "unknown";
build = "unknown";
url = "/sdk";

req  = string("POST ", url, " HTTP/1.1\r\n");
req += string("Host: ", host, "\r\n");
req += string("Content-Type: application/x-www-form-urlencoded\r\n");
req += string("Content-Length: 348\r\n\r\n");
req += string('
<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
\t\t\t<env:Body>
\t\t\t<RetrieveServiceContent xmlns="urn:vim25">
\t\t\t\t<_this type="ServiceInstance">ServiceInstance</_this>
\t\t\t</RetrieveServiceContent>
\t\t\t</env:Body>
</env:Envelope>');
req += string("\r\n");

send(socket:soc, data:req);
buf = recv(socket:soc, length:8192);
close(soc);

if("RetrieveServiceContentResponse" >< buf) {

  if("<fullName>VMware vCenter" >< buf)
    exit(0);

  if("ESXi" >< buf)
    type = "ESXi";

  version = eregmatch(pattern:"<version>([0-9.]+)</version>", string:buf);
  if(!isnull(version[1]))
    vers = version[1];

  name = eregmatch(pattern:"<name>(.*)</name>", string:buf);
  if(!isnull(name[1]))
    type = name[1];

  if("<build>" >< buf) {
    _build = eregmatch(pattern:"<build>([0-9]+)</build>", string:buf);
    if(!isnull(_build[1])) {
      replace_kb_item(name:"VMware/ESX/build", value:_build[1]);
      build = _build[1];
    }
  }

  r = eregmatch(pattern:"<returnval>(.*)</returnval>", string:buf);
  if(!isnull(r[1]))
    rs = r[1];
}

if("ESXi" >< type) {
  cpe_string = "cpe:/o:vmware:esxi";
  set_kb_item(name:"VMware/ESX/type/ESXi", value:TRUE); # ESXi
} else {
  cpe_string = "cpe:/o:vmware:esx";
  set_kb_item(name:"VMware/ESX/type/ESXs", value:TRUE); # ESX Server
}

if(vers != "unknown")
  cpe = build_cpe(value:vers, exp:"^([0-9.a-z]+)", base:cpe_string + ":");
else
  cpe = cpe_string;

os_register_and_report(os:"VMware ESX / ESXi", cpe:cpe, banner_type:"HTTP Login Page / API", port:port, desc:SCRIPT_DESC, runs_key:"unixoide");

set_kb_item(name:"VMware/GSX-Server/web/version", value:vers);
set_kb_item(name:"VMware/ESX/version", value:vers);
set_kb_item(name:"VMware/ESX/installed", value:TRUE);
set_kb_item(name:"VMware/ESX/port", value:port);

log_message(data:build_detection_report(app:type,
                                        version:vers,
                                        build:build,
                                        install:"/",
                                        cpe:cpe,
                                        concludedUrl:http_report_vuln_url(port:port, url:url, url_only:TRUE),
                                        concluded:rs),
            port:port);

exit(0);
