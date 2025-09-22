# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:limesurvey:limesurvey";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140848");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2018-03-05 09:07:18 +0700 (Mon, 05 Mar 2018)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-23 16:28:00 +0000 (Fri, 23 Mar 2018)");

  script_cve_id("CVE-2018-7556");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("LimeSurvey 2.6.x < 2.6.7, 2.7x.x < 2.73.1, 3.x.x < 3.4.2 File Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_limesurvey_detect.nasl");
  script_mandatory_keys("limesurvey/http/detected");

  script_tag(name:"summary", value:"LimeSurvey mishandles
  application/controller/InstallerController.php after installation, which allows remote attackers
  to access the configuration file.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"LimeSurvey version 2.6.0 through 2.6.7, 2.7.0 through 2.73.1
  and 3.0.0 through 3.4.2.");

  script_tag(name:"solution", value:"Update to version 2.6.7 LTS, 2.73.1, 3.4.2 or later.");

  script_xref(name:"URL", value:"https://www.limesurvey.org/about-us/news/2075-limesurvey-security-advisory-02-2018");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "2.6.0", test_version2: "2.6.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.6.7");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.7.0", test_version2: "2.73.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.73.1");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.0.0", test_version2: "3.4.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.4.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
