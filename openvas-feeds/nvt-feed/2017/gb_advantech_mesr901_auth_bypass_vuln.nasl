# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:advantech:mesr901";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106843");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-06-02 11:02:25 +0700 (Fri, 02 Jun 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:29:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2017-7909");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Advantech MESR901 Authentication Bypass Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_advantech_mesr901_detect.nasl");
  script_mandatory_keys("advantech_mesr901/detected");

  script_tag(name:"summary", value:"Advantech MESR901 is prone to an authentication bypass vulnerability.");

  script_tag(name:"insight", value:"The web interface uses JavaScript to check client authentication and
redirect unauthorized users. Attackers may intercept requests and bypass authentication to access restricted web
pages.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET Request and checks the response.");

  script_tag(name:"affected", value:"Advantech MESR901 firmware versions 1.5.2 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-122-03");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/network.html";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if ("I want DHCP to setup the network" >< res && "validateIPAddrAndGateway(this)" >< res) {
  report = "It was possible to access " + http_report_vuln_url(port: port, url: url, url_only: TRUE) +
           " without authentication.\n";

  gateway = eregmatch(pattern: 'default_gateway.* VALUE="([0-9.]+)" CLASS', string: res);
  if (!isnull(gateway[1]))
    report += "\nThis is the obtained default gateway of the MESR901:     " + gateway[1];

  security_message(port: port, data: report);
  exit(0);
}

exit(99);
