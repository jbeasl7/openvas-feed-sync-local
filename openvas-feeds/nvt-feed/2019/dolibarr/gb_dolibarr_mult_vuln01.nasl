# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dolibarr:dolibarr";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141823");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2019-01-04 11:04:34 +0700 (Fri, 04 Jan 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-09 13:12:00 +0000 (Wed, 09 Jan 2019)");

  script_cve_id("CVE-2018-19992", "CVE-2018-19993", "CVE-2018-19994", "CVE-2018-19995",
                "CVE-2018-19998");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dolibarr < 8.0.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dolibarr_http_detect.nasl");
  script_mandatory_keys("dolibarr/detected");

  script_tag(name:"summary", value:"Dolibarr is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Dolibarr is prone to multiple vulnerabilities:

  - CVE-2018-19992: A stored cross-site scripting (XSS) allows remote authenticated users to inject
  arbitrary web script or HTML via the 'address' (POST) or 'town' (POST) parameter to
  adherents/type.php

  - CVE-2018-19993: A reflected cross-site scripting (XSS) allows remote attackers to inject
  arbitrary web script or HTML via the transphrase parameter to public/notice.php

  - CVE-2018-19994: An error-based SQL injection in product/card.php allows remote authenticated
  users to execute arbitrary SQL commands via the desiredstock parameter

  - CVE-2018-19995: A stored cross-site scripting (XSS) allows remote authenticated users to inject
  arbitrary web script or HTML via the 'address' (POST) or 'town' (POST) parameter to user/card.php

  - CVE-2018-19998: SQL injection in user/card.php allows remote authenticated users to execute
  arbitrary SQL commands via the employee parameter");

  script_tag(name:"affected", value:"Dolibarr prior to version 8.0.4.");

  script_tag(name:"solution", value:"Update to version 8.0.4 or later.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "8.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
