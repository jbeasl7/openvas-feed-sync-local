# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:openmeetings";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112064");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-10-05 14:56:22 +0200 (Thu, 05 Oct 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-19 16:12:00 +0000 (Wed, 19 Jul 2017)");

  script_cve_id("CVE-2017-7664");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache OpenMeetings Missing XML Validation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_openmeetings_http_detect.nasl");
  script_mandatory_keys("apache/openmeetings/detected");

  script_tag(name:"summary", value:"Apache OpenMeetings is prone to a missing XML validation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In Apache OpenMeetings uploaded XML documents were not
  correctly validated.");

  script_tag(name:"affected", value:"Apache OpenMeetings version 3.1.0 through 3.2.1.");

  script_tag(name:"solution", value:"Update to version 3.3.0 or later.");

  script_xref(name:"URL", value:"https://openmeetings.apache.org/security.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99576");

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

if (version_in_range(version: version, test_version: "3.1.0", test_version2: "3.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
