# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:icinga:icinga2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128140");
  script_version("2025-05-30T05:40:08+0000");
  script_tag(name:"last_modification", value:"2025-05-30 05:40:08 +0000 (Fri, 30 May 2025)");
  script_tag(name:"creation_date", value:"2025-05-28 09:42:10 +0000 (Wed, 28 May 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2025-48057");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Icinga < 2.12.12, 2.13.0 < 2.13.12, 2.14.0 < 2.14.6 Certificate Validation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_icinga2_http_detect.nasl");
  script_mandatory_keys("icinga2/detected");

  script_tag(name:"summary", value:"Icinga 2 is prone to a TLS server certificate validation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A logic error in certificate validation can allow attackers to
  impersonate trusted nodes in a monitoring network by tricking the system into renewing a
  certificate using a malicious request.");

  script_tag(name:"affected", value:"Icinga2 versions prior to 2.12.12, 2.13.0 prior to 2.13.12
  and 2.14.0 prior to 2.14.6.");

  script_tag(name:"solution", value:"Update to version 2.12.12, 2.13.12, 2.14.6 or later.");

  script_xref(name:"URL", value:"https://github.com/Icinga/icinga2/security/advisories/GHSA-7vcf-f5v9-3wr6");

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

if (version_is_less(version: version, test_version: "2.12.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.12.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "2.13.0", test_version_up: "2.13.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.13.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "2.14.0", test_version_up: "2.14.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.14.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
