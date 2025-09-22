# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:openmeetings";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808658");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-08-23 15:09:03 +0530 (Tue, 23 Aug 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-01 20:46:00 +0000 (Fri, 01 Mar 2019)");

  script_cve_id("CVE-2016-3089", "CVE-2016-8736");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache OpenMeetings < 3.1.2 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_openmeetings_http_detect.nasl");
  script_mandatory_keys("apache/openmeetings/http/detected");
  script_require_ports("Services/www", 5443);

  script_tag(name:"summary", value:"Apache OpenMeetings is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2016-3089: Improper sanitization of input to 'swf'query parameter in swf panel

  - CVE-2016-8736: Remote code execution (RCE) via RMI deserialization attack");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute:

  - arbitrary script code in a user's browser session within the trust relationship between their
  browser and the server

  - remote commands via RMI attacks against the server");

  script_tag(name:"affected", value:"Apache OpenMeetings prior to version 3.1.2.");

  script_tag(name:"solution", value:"Update to version 3.1.2 or later.");

  script_xref(name:"URL", value:"http://openmeetings.apache.org/security.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92442");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94145");
  script_xref(name:"URL", value:"https://www.apache.org/dist/openmeetings/3.1.2/CHANGELOG");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + '/swf?swf=%3Cscript%3Ealert%28document.cookie%29%3C/script%3E';

if (http_vuln_check(port: port, url: url, check_header: TRUE,
                    pattern: "<script>alert\(document\.cookie\)</script>",
                    extra_check: make_list(">OpenMeetings<", ">Timezone<"))) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
