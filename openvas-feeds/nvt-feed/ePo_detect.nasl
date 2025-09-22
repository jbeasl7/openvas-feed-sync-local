# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100329");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-01-31T05:37:27+0000");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-10-30 14:42:19 +0100 (Fri, 30 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("McAfee ePO Agent Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Service detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8081);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of the McAfee ePO Agent.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:8081);

url = "/";
buf = http_get_cache(port: port, item: url);

if ("Agent-ListenServer" >< buf && "displayResult()" >< buf) {
  domain = get_kb_item("SMB/name");

  if (!domain) {
    ip = get_host_ip();
    hostname = http_host_name(dont_add_port: TRUE);

    if(ip != hostname) {
      host = split(hostname, sep:".", keep:FALSE);
      if (!isnull(host[0]))
        domain = host[0];
    }
  }

  if (domain) {
    url = '/Agent_' + domain + '.xml';
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  }
}

if (egrep(pattern:"Agent-ListenServer", string: buf, icase: TRUE) ||
    (egrep(pattern:"naLog>", string: buf, icase: FALSE) &&
     egrep(pattern:"ComputerName>", string: buf, icase: FALSE) &&
     egrep(pattern:"FrameworkLog", string: buf, icase: FALSE))) {
  info_head = "\n\nInformation that was gathered from url '" + url +"' on port " + port + '.\n\n';

  if (buf =~ "^HTTP/1\.[01] 403")
    info += "Could not read remote log. Error: 403 Forbidden\n";
  else {
    if (lines = split(buf, sep:'><', keep: TRUE)) {
      foreach line (lines) {
        if (computer_name = eregmatch(string: line, pattern: 'ComputerName>([^<]+)</ComputerName>', icase: TRUE))
          if (!isnull(computer_name[1]))
            cn = computer_name[1];

        if (version = eregmatch(string: line, pattern: "version>([^<]+)</version>", icase: TRUE))
          if (!isnull(version[1])) {
            vers = version[1];
            concVers = version[0];
          }

        if (connected = eregmatch(string: line, pattern: 'Log component="[0-9]+" time="([^"]+)" type="3">(Agent is connecting to ePO server|Agent stellt Verbindung zu ePO-Server her)</Log>',icase: TRUE))
          if (!isnull(connected[1]))
            co = connected[1];

        if (repServer = eregmatch(string: line, pattern: 'Log component=[^>]+>Checking update packages from repository ([a-zA-Z0-9_-]+).</Log',icase: FALSE))
          if (!isnull(repServer[1]))
            rserver = repServer[1];

        if (isnull(rserver))
          if (repServer = eregmatch(string:line, pattern: "ePOServerName>([^<]+)</ePOServerName>"))
           if (!isnull(repServer[1]))
             rserver = repServer[1];
      }
    }
  }

  set_kb_item(name: "mcafee_epo_agent/installed", value: TRUE);
  service_register(port: port,  ipproto: "tcp", proto: "ePoAgent");

  if (!isnull(cn))
    info += "ComputerName:               " + cn + '\n';

  if (!isnull(vers))
    info += "ClientVersion:              " + vers + '\n';

  if (!isnull(rserver))
    info += "Repository-Server:          " + rserver + '\n';

  if (!isnull(co))
    info += "Last connect to ePo-Server: " + co + '\n';

  if (info)
    extra = info_head + info;

  cpe = build_cpe(value: vers, exp: "^([0-9.]+)", base: "cpe:/a:mcafee:agent:");
  if (!cpe)
    cpe = "cpe:/a:mcafee:agent";

  register_product(cpe: cpe, location: port + "/tcp", port: port);

  log_message(data: build_detection_report(app: "McAfee ePO Agent", version: vers, install: port + "/tcp", cpe: cpe,
                                           concluded: concVers, extra: extra),
              port: port);
  exit(0);
}

exit(0);
