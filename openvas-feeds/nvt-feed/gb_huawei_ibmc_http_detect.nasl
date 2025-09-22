# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141140");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-06-06 08:31:14 +0700 (Wed, 06 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Huawei iBMC Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Huawei iBMC.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("url_func.inc");
include("misc_func.inc");
include("string_hex_func.inc");

port = http_get_port(default: 443);

res = http_get_cache(port: port, item: "/login.html");

if ("<title>iBMC Login</title>" >< res && "lnkNetAddr" >< res) {
  version = "unknown";
  model = "unknown";

  set_kb_item(name: "huawei/ibmc/detected", value: TRUE);
  set_kb_item(name: "huawei/data_communication_product/detected", value: TRUE);
  set_kb_item(name: "huawei/ibmc/http/port", value: port);

  url = "/bmc/php/getmultiproperty.php";
  data = "str_input=" +
         urlencode(str: '[{"class_name":"BMC","obj_name":"BMC","property_list":["SystemName","HostName"]}]');

  req = http_post_put_req(port: port, url: url, data: data,
                          add_headers: make_array("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8",
                                                  "X-Requested-With", "XMLHttpRequest"),
                          accept_header: "application/json, text/javascript, */*; q=0.01");
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  res = urldecode(estr: res);
  mod = eregmatch(pattern: '"SystemName": "([^"]+)', string: res);
  if (!isnull(mod[1])) {
    model = mod[1];
    set_kb_item(name: "huawei/ibmc/http/" + port + "/concluded", value: res);
    set_kb_item(name: "huawei/ibmc/http/" + port + "/concludedUrl", value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
  }

  set_kb_item(name: "huawei/ibmc/http/" + port + "/version", value: version);
  set_kb_item(name: "huawei/ibmc/http/" + port + "/model", value: model);
}

exit(0);
