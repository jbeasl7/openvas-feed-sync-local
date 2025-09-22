# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:openmeetings";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112063");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-10-05 14:45:22 +0200 (Thu, 05 Oct 2017)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-7663", "CVE-2017-7682");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache OpenMeetings 3.2.x Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_openmeetings_http_detect.nasl");
  script_mandatory_keys("apache/openmeetings/detected");

  script_tag(name:"summary", value:"Apache OpenMeetings is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2017-7663: Both global and Room chat are vulnerable to XSS attack

  - CVE-2017-7682: Parameter manipulation attacks");

  script_tag(name:"affected", value:"Apache OpenMeetings version 3.2.x.");

  script_tag(name:"solution", value:"Update to version 3.3.0 or later.");

  script_xref(name:"URL", value:"https://openmeetings.apache.org/security.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99577");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port:port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "3.2.0", test_version_up: "3.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
