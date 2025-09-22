# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141032");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-04-26 11:30:45 +0700 (Thu, 26 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Draytek VigorACS Detection");

  script_tag(name:"summary", value:"Detection of Draytek VigorACS.

  The script sends a connection request to the server and attempts to detect Draytek VigorACS and to extract its
  version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.draytek.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default: 8080);

# 1.x: /web/ACS.html, 2.x: /web/
foreach url (make_list("/web/", "/web/ACS.html")) {
  res = http_get_cache(port: port, item: url);

  if ("<title>VigorACS Central Management System</title>" >!< res && "<title>VigorACS</title>" >!< res)
    continue;

  version = "unknown";

  # version 1.x
  # var acsVersion="1.0.8.1";
  # var acsVersion="1.1.12beta8";
  vers = eregmatch(pattern: 'acsVersion="([^"]+)"', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = url;
  }
  # version 2.x
  else {
    p_url = "/ACSServer/Html5Servlet";
    data = '{"act":"AboutVigorACS","action":"version","actionType":1}';
    req = http_post_put_req(port: port, url: p_url, data: data,
                        add_headers: make_array("Content-Type", "application/json"));
    res = http_keepalive_send_recv(port: port, data: req);

    # e.g. {"version":"2.3.0beta1_r7778"}
    vers = eregmatch(pattern: '\\{"version":"([^"]+)"\\}', string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      concUrl = p_url;
    }
  }

  set_kb_item(name: "draytek_vigoracs/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9a-z._]+)", base: "cpe:/a:draytek:vigoracs:");
  if (!cpe)
    cpe = 'cpe:/a:draytek:vigoracs';

  register_product(cpe: cpe, location: "/web", port: port);

  log_message(data: build_detection_report(app: "Draytek VigorACS", version: version, install: "/web", cpe: cpe,
                                           concluded: vers[0], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
