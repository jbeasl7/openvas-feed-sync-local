# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:roller";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142641");
  script_version("2024-11-05T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-11-05 05:05:33 +0000 (Tue, 05 Nov 2024)");
  script_tag(name:"creation_date", value:"2019-07-23 09:21:49 +0000 (Tue, 23 Jul 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-14 12:19:00 +0000 (Tue, 14 Sep 2021)");

  script_cve_id("CVE-2019-0234");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Roller < 5.2.3 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_roller_http_detect.nasl");
  script_mandatory_keys("apache/roller/detected");

  script_tag(name:"summary", value:"Apache Roller is prone to a reflected cross-site scripting
  (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Roller's Math Comment Authenticator did not property sanitize
  user input and could be exploited to perform reflected cross-site scripting.");

  script_tag(name:"affected", value:"Apache Roller versions 5.2, 5.2.1 and 5.2.2. The unsupported
  pre-Roller 5.1 versions may also be affected.");

  script_tag(name:"solution", value:"Update to version 5.2.3 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/26cdef3fa8a8fa7fcbb99320aa860836ead124b414c654a4d12674cf@%3Cdev.roller.apache.org%3E");

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

if (version_is_less(version: version, test_version: "5.2.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
