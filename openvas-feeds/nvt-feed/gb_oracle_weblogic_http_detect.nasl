# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100493");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-02-19T14:37:31+0000");
  script_tag(name:"last_modification", value:"2024-02-19 14:37:31 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-02-14 12:35:00 +0100 (Sun, 14 Feb 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Oracle WebLogic Server Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 7001);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Oracle WebLogic Server.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default: 7001);
banner = http_get_remote_headers(port: port);

version = "unknown";
servicepack = "unknown";

if (banner =~ "Server: WebLogic ") {
  # Server: WebLogic Server 7.0 SP5 Wed Mar 31 23:12:50 PST 2004 363281
  # Server: Weblogic 12.2.1.1
  # Server: WebLogic Server 10.3.6.0.171017 PSU Patch for BUG26519424 TUE SEP 12 18:34:42 IST 2017
  # Server: WebLogic 5.1.0 Service Pack 6 09/20/2000 21:03:19 #84511
  # Server: WebLogic WebLogic Server 6.1 SP2  12/18/2001 11:13:46 #154529
  vers = eregmatch(pattern: "WebLogic (Server )?([0-9.]+)( (SP|Service Pack )([0-9]+))?", string: banner,
                   icase: TRUE);
  if (!isnull(vers[2])) {
    version = vers[2];
    set_kb_item(name: "oracle/weblogic/http/" + port + "/concluded", value: vers[0]);
    url = "/";
    if (!isnull(vers[5]))
      servicepack = vers[5];
  }
} else {
  url = "/console/login/LoginForm.jsp";

  buf = http_get_cache(item: url, port: port);

  if (buf && (buf =~ "<title>(Oracle|BEA) WebLogic Server Administration Console" ||
              egrep(pattern: "<TITLE>WebLogic Server.*Console Login", string: buf))) {

    vers = eregmatch(string: buf, pattern: "WebLogic Server ([0-9.]+)", icase: TRUE);
    if (!isnull(vers[1])){
      version = vers[1];
      set_kb_item(name: "oracle/weblogic/http/" + port + "/concluded", value: vers[0]);
    } else {
      vers = eregmatch(string: buf, pattern: "WebLogic Server Version: ([0-9.]+)", icase: TRUE);
      if (!isnull(vers[1])) {
        version = vers[1];
        set_kb_item(name: "oracle/weblogic/http/" + port + "/concluded", value: vers[0]);
      }
    }
  } else {
    exit(0);
  }
}

endpoints = make_array(
"/_async/AsyncResponseService?WSDL", "www\.bea\.com/async/AsyncResponseService",
"/_async/AsyncResponseServiceHttps?WSDL", "www\.bea\.com/async/AsyncResponseService",
"/_async/AsyncResponseServiceJms?WSDL", "www\.bea\.com/async/AsyncResponseService",
"/_async/AsyncResponseServiceSoap12?WSDL", "www\.bea\.com/async/AsyncResponseService",
"/_async/AsyncResponseServiceSoap12Https?WSDL", "www\.bea\.com/async/AsyncResponseService",
"/_async/AsyncResponseServiceSoap12Jms?WSDL", "www\.bea\.com/async/AsyncResponseService",
"/wls-wsat/CoordinatorPortType", "weblogic\.wsee\.wstx\.wsat\.v1[01]\.endpoint\.CoordinatorPort",
"/wls-wsat/CoordinatorPortType11", "weblogic\.wsee\.wstx\.wsat\.v1[01]\.endpoint\.CoordinatorPort",
"/wls-wsat/ParticipantPortType", "weblogic\.wsee\.wstx\.wsat\.v1[01]\.endpoint\.ParticipantPort",
"/wls-wsat/ParticipantPortType11", "weblogic\.wsee\.wstx\.wsat\.v1[01]\.endpoint\.ParticipantPort",
"/wls-wsat/RegistrationPortTypeRPC", "weblogic\.wsee\.wstx\.wsc\.v1[01]\.endpoint\.RegistrationPort",
"/wls-wsat/RegistrationRequesterPortType", "weblogic\.wsee\.wstx\.wsc\.v1[01]\.endpoint\.RegistrationRequesterPort",
"/wls-wsat/RegistrationPortTypeRPC11", "weblogic\.wsee\.wstx\.wsc\.v1[01]\.endpoint\.RegistrationPort");

foreach endpoint (keys(endpoints)) {

  check = endpoints[endpoint];

  req = http_get(port: port, item: endpoint);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  if (res && eregmatch(string: res, pattern: check, icase: FALSE))
    set_kb_item(name: "oracle/weblogic/http/" + port + "/found_service_urls",
                value: http_report_vuln_url(port: port, url: endpoint, url_only: TRUE));
}

set_kb_item(name: "oracle/weblogic/detected", value: TRUE);
set_kb_item(name: "oracle/weblogic/http/detected", value: TRUE);
set_kb_item(name: "oracle/weblogic/http/port", value: port);
set_kb_item(name: "oracle/weblogic/http/" + port + "/concludedUrl",
            value: http_report_vuln_url(port: port, url: url, url_only: TRUE));

set_kb_item(name: "oracle/weblogic/http/" + port + "/version", value: version);
set_kb_item(name: "oracle/weblogic/http/" + port + "/servicepack", value: servicepack);

exit(0);
