# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# nb: Running against all DCS devices just to be sure as the vendor is known to usually have a wide
# range of affected devices even not actually mentioned as affected.
CPE_PREFIX = "cpe:/o:dlink:dcs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805034");
  script_version("2025-06-27T15:42:32+0000");
  script_tag(name:"last_modification", value:"2025-06-27 15:42:32 +0000 (Fri, 27 Jun 2025)");
  script_tag(name:"creation_date", value:"2015-01-08 11:21:29 +0530 (Thu, 08 Jan 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2014-9517");

  # nb: Not really a reliable response check below...
  script_tag(name:"qod_type", value:"remote_probe");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("D-Link DCS-2103 IP Camera Devices < 1.20 XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dcs_consolidation.nasl");
  script_mandatory_keys("d-link/dcs/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"D-Link DCS-2103 IP camera devices are prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to an input passed via the vb.htm script to the
  'QUERY_STRING ' parameter is not properly sanitized.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"D-Link DCS-2103 IP camera devices with firmware versions prior
  to 1.20. Other models might be affected as well.");

  script_tag(name:"solution", value:"- D-Link DCS-2103 devices: Update to version 1.20 or later

  - Other models: Please contact the vendor for more information");

  script_xref(name:"URL", value:"https://packetstorm.news/files/id/129609");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2014/Dec/85");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www"))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if (!get_app_location(cpe: cpe, port: port, nofork: TRUE))
  exit(0);

pattern = "<script>alert\(document\.cookie\)</script>";
url = "/vb.htm?<script>alert(document.cookie)</script>";

if (concl = http_vuln_check(port: port, url: url, check_header: TRUE,
                            pattern: pattern)) {

  report = http_report_vuln_url(port: port, url: url);

  concl = egrep(string: concl, pattern: pattern, icase: TRUE);
  if (concl)
    report += '\nResponse:\n\n' + chomp(concl);

  security_message(port: port, data: report);
  exit(0);
}

exit(99);
