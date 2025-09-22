# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:raritan:power_iq";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106818");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-05-22 15:05:20 +0700 (Mon, 22 May 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Raritan PowerIQ Rails RCE Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_raritan_poweriq_detect.nasl");
  script_mandatory_keys("raritan_poweriq/detected");

  script_tag(name:"summary", value:"Raritan PowerIQ is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"insight", value:"Raritan PowerIQ versions 4.1, 4.2, and 4.3 ship with a Rails 2 web interface
  with a hardcoded session secret of 8e238c9702412d475a4c44b7726a0537.");

  script_tag(name:"impact", value:"An unauthenticated attacker may execute arbitrary code as the nginx user.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP request and checks the response.");

  script_tag(name:"affected", value:"Raritran PowerIQ version 4.1, 4.2 and 4.3.");

  script_tag(name:"solution", value:"Upgrade to the latest version.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/130797/raritanpoweriq-staticsecret.txt");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");
include("string_hex_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/login/login";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if ("Set-Cookie: _session_id" >!< res)
  exit(99);

cookie = eregmatch(pattern: "Set-Cookie: _session_id=([A-Za-z0-9%]*)--([0-9A-Fa-f]+);", string: res);
if (isnull(cookie[1]) || isnull(cookie[2]))
  exit(99);

data = urldecode(estr: cookie[1]);

SECRET = '8e238c9702412d475a4c44b7726a0537';

hash = hexstr(HMAC_SHA1(data: data, key: SECRET));

if (hash == cookie[2]) {
  report = "It was possible to confirm that Rails uses the 'secret_token' '8e238c9702412d475a4c44b7726a0537'\n";
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
