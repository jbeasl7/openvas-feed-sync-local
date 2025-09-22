# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106288");
  script_version("2024-07-04T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-07-04 05:05:37 +0000 (Thu, 04 Jul 2024)");
  script_tag(name:"creation_date", value:"2016-09-27 11:26:32 +0700 (Tue, 27 Sep 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dell / EMC Avamar Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Dell / EMC Avamar.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/dtlt/home.html";

res = http_get_cache(port: port, item: url);

if ((res =~ "<title>(EMC )?Avamar" && "dtlt-banner-product-name-avamar" >< res) || "Server: Avamar" >< res) {
  version = "unknown";
  location = "/";
  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  permut = rand_str(length: 32, charset: "ABCDEF1234567890");

  url = "/avi/avigui/avigwt";

  headers = make_array("Content-Type", "text/x-gwt-rpc; charset=utf-8",
                       "X-GWT-Permutation", permut,
                       "'X-GWT-Module-Base", http_host_name(port: port) + "/avi/avigui/");

  data = '5|0|6|https://' + get_host_ip() + '/avi/avigui/|' +
         rand_str(length: 32, charset: "ABCDEF1234567890") +
         '|com.avamar.avinstaller.gwt.shared.AvinstallerService|getAviVersion|java.lang.String/|' +
         get_host_ip() + '|1|2|3|4|1|5|6|';

  req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req);

  if (res && '//OK[1,["' >< res) {
    # //OK[1,["7.3.1.125"],0,7]
    vers = eregmatch(pattern: '\\["([0-9.-]+)"\\]', string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      set_kb_item(name: "dell/avamar/http/" + port + "/concluded", value: vers[0]);
      conclUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    }
  }

  if (version == "unknown") {
    url = "/dtlt/wr_about.html";
    req = http_get(port: port, item: url);
    res = http_keepalive_send_recv(port: port, data: req);

    # <div id="aboutVersion"> Version 19.8.0
    vers = eregmatch(pattern: "Version ([0-9.]+)", string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      set_kb_item(name: "dell/avamar/http/" + port + "/concluded", value: vers[0]);
      conclUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    }
  }

  set_kb_item(name: "dell/avamar/detected", value: TRUE);
  set_kb_item(name: "dell/avamar/http/detected", value: TRUE);
  set_kb_item(name: "dell/avamar/http/port", value: port);
  set_kb_item(name: "dell/avamar/http/" + port + "/concludedUrl", value: conclUrl);

  set_kb_item(name: "dell/avamar/http/" + port + "/version", value: version);

  exit(0);
}

exit(0);
