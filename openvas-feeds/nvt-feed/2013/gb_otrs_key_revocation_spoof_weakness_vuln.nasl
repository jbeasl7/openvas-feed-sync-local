# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803932");
  script_version("2025-07-17T05:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"creation_date", value:"2013-09-22 15:18:31 +0530 (Sun, 22 Sep 2013)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2010-4764");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS < 2.4.10, 3.x < 3.0.3 Key Revocation Spoofing Weakness Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_otrs_http_detect.nasl");
  script_mandatory_keys("otrs/detected");

  script_tag(name:"summary", value:"Open Ticket Request System (OTRS) is prone to a spoofing
  weakness vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error exists in the application which fails to present
  warnings about incoming encrypted e-mail messages that were based on revoked PGP or GPG keys.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to spoof
  e-mail communication by leveraging a key that has a revocation signature.");

  script_tag(name:"affected", value:"OTRS versions prior to 2.4.10 and 3.x prior to 3.0.3.");

  script_tag(name:"solution", value:"Update to version 2.4.10, 3.0.3 or later.");


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

if (version_is_less(version: version, test_version: "2.4.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.0", test_version2: "3.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
