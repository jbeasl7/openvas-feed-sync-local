# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:wicket";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107117");
  script_version("2025-04-01T05:39:41+0000");
  script_tag(name:"last_modification", value:"2025-04-01 05:39:41 +0000 (Tue, 01 Apr 2025)");
  script_tag(name:"creation_date", value:"2017-01-02 13:26:09 +0100 (Mon, 02 Jan 2017)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-06 19:15:00 +0000 (Mon, 06 May 2019)");

  script_cve_id("CVE-2016-6793");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Wicket DoS Vulnerability (Dec 2016)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_apache_wicket_consolidation.nasl");
  script_mandatory_keys("apache/wicket/detected");

  script_tag(name:"summary", value:"Apache Wicket is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Depending on the ISerializer set in the Wicket application,
  it's possible that a Wicket object deserialized from an untrusted source and utilized by the
  application causes the code to enter an infinite loop.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause
  the application to enter an infinite loop and consume excessive CPU resources, resulting in
  denial-of-service conditions.");

  script_tag(name:"affected", value:"Apache Wicket versions 1.5.x through 1.5.16 and 6.x through
  6.24.0.");

  script_tag(name:"solution", value:"Update to version 1.5.17, 6.25.0 or later.");

  script_xref(name:"URL", value:"https://wicket.apache.org/news/2016/12/31/cve-2016-6793.html");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210123210311/http://www.securityfocus.com/bid/95168");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "1.5.0", test_version2: "1.5.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.5.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "6.0.0", test_version2: "6.24.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.25.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
