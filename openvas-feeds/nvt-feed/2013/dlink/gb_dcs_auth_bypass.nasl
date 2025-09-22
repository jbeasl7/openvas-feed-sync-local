# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# nb: Running against all DCS devices just to be sure as the vendor is known to usually have a wide
# range of affected devices even not actually mentioned as affected.
CPE_PREFIX = "cpe:/o:dlink:dcs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103647");
  script_version("2025-06-27T15:42:32+0000");
  script_tag(name:"last_modification", value:"2025-06-27 15:42:32 +0000 (Fri, 27 Jun 2025)");
  script_tag(name:"creation_date", value:"2013-01-30 11:53:42 +0100 (Wed, 30 Jan 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("D-Link DCS IP Camera Devices Authentication Bypass Vulnerability (Jan 2013) - Active Check");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dcs_consolidation.nasl");
  script_mandatory_keys("d-link/dcs/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Multiple D-Link DCS IP camera devices are prone to an
  authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to bypass authentication and to
  execute commands due to a remote information disclosure of the configuration.");

  script_tag(name:"affected", value:"The following devices are known to be affected:

  - D-Link DCS-930L with firmware version 1.04 and probably prior

  - D-Link DCS-932L with firmware version 1.02 and probably prior

  Other models might be affected as well.");

  script_tag(name:"solution", value:"Updates are available. Please see the reference for more
  information.");

  script_xref(name:"URL", value:"https://packetstorm.news/files/id/119902");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!infos = get_app_port_from_cpe_prefix(cpe:CPE_PREFIX, service:"www"))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if(!get_app_location(cpe:cpe, port:port, nofork:TRUE))
  exit(0);

url = "/frame/GetConfig";
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

# nb: "=~" for case insensitity for both is expected here to catch as much as possible different
# possible responses...
if(buf =~ "Content-Transfer-Encoding\s*:\s*binary" && buf =~ 'filename="Config\\.CFG"') {

  report = http_report_vuln_url(port:port, url:url);

  concl = egrep(string: buf, pattern: 'filename="Config\\.CFG"', icase: TRUE);
  if (concl)
    report += '\nResponse:\n\n' + chomp(concl);

  security_message(port:port, data:report);
  exit(0);
}

exit(99);
