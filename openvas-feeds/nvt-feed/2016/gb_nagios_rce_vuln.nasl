# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nagios:nagios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106473");
  script_version("2025-09-11T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-12-15 10:22:34 +0700 (Thu, 15 Dec 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 20:00:00 +0000 (Tue, 09 Oct 2018)");

  script_cve_id("CVE-2016-9565");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nagios RCE Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nagios_http_detect.nasl");
  script_mandatory_keys("nagios/detected");

  script_tag(name:"summary", value:"Nagios is prone to a remote command execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is caused by the use of a vulnerable component for
handling RSS news feeds - MagpieRSS in Nagios Core control panel/front-end. The component is used by Nagios
front-end to load news feeds from remote feed source upon log-in. The component was found vulnerable to
CVE-2008-4796 which fix was incomplete.");

  script_tag(name:"impact", value:"An attacker who manages to impersonate the feed source, may be able to
inject malicious parameters to curl command and effectively read/write arbitrary files on the target Nagios
server which finally may lead to arbitrary code execution.");

  script_tag(name:"affected", value:"Nagios before version 4.2.2.");

  script_tag(name:"solution", value:"Update to version 4.2.2 or later.");

  script_xref(name:"URL", value:"http://legalhackers.com/advisories/Nagios-Exploit-Command-Injection-CVE-2016-9565-2008-4796.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
