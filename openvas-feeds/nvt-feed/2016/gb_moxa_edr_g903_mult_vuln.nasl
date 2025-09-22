# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:moxa:edr-g903";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808220");
  script_version("2025-03-20T05:38:32+0000");
  script_cve_id("CVE-2016-0875", "CVE-2016-0876", "CVE-2016-0877", "CVE-2016-0878",
                "CVE-2016-0879");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-12 18:05:00 +0000 (Tue, 12 Apr 2022)");
  script_tag(name:"creation_date", value:"2016-06-09 13:45:38 +0530 (Thu, 09 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("Moxa EDR G903 Router Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Moxa EDR G903 Router is prone to multiple vulnerabilities");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to access sensitive data.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The copies of configuration and log files are not deleted after completing
    the import function.

  - The configuration and log files can be accessed without authentication.

  - An improper validation of 'ping' function.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to obtain sensitive information by accessing sensitive files
  and also to cause a denial of service (memory consumption).");

  script_tag(name:"affected", value:"Moxa EDR-G903 Versions V3.4.11 and older.");

  script_tag(name:"solution", value:"Upgrade to firmware version v3.4.12 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-042-01");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moxa_edr_g903_remote_detect.nasl");
  script_mandatory_keys("Moxa/EDR/G903/Installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if (!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

url = "/xml/net_led_xml";

if(http_vuln_check(port:port, url:url, check_header:TRUE,
                   pattern:"<eth[0-9]>[0-9.]+</eth[0-9]>",
                   extra_check:"<thermal>")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
