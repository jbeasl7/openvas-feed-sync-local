# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sierra_wireless:acemanager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106076");
  script_version("2024-01-16T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-01-16 05:05:27 +0000 (Tue, 16 Jan 2024)");
  script_tag(name:"creation_date", value:"2016-05-17 09:27:34 +0700 (Tue, 17 May 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-17 17:42:00 +0000 (Thu, 17 Jun 2021)");

  script_cve_id("CVE-2015-6479");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sierra Wireless AceManager File Disclosure Vulnerability (ICSA-16-105-01) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_sierrawireless_acemanager_http_detect.nasl");
  script_mandatory_keys("sierra_wireless/acemanager/http/detected");
  script_require_ports("Services/www", 9443);

  script_tag(name:"summary", value:"Sierra Wireless AceManager is prone to a file disclosure
  vulnerability");

  script_tag(name:"vuldetect", value:"Checks if the file filteredlogs.txt is accessible.");

  script_tag(name:"insight", value:"The file filteredlogs.txt is available without authorization.
  No sensitive information is written to the accessible log file, although because of the
  diagnostic nature of such files an attacker may be able to learn operational characteristics of
  the device, e.g., the sequence of operations at boot time. The accessible log file only persists
  until the next log view operation or until the device reboots.");

  script_tag(name:"impact", value:"An attacker may be able to learn operational characteristics of
  the gateway, e.g., the sequence of operations at boot time.");

  script_tag(name:"affected", value:"ALEOS 4.4.2 and earlier.");

  script_tag(name:"solution", value:"Update to version 4.4.4 or later.");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-105-01");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url =  "/filteredlogs.txt";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if ("ALEOS_EVENTS_" >< res || "ALEOS_WAN_" >< res) {
  report = http_report_vuln_url(port: port, url:url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
