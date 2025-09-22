# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:icinga:icinga2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146541");
  script_version("2024-11-15T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-15 05:05:36 +0000 (Fri, 15 Nov 2024)");
  script_tag(name:"creation_date", value:"2021-08-20 09:42:10 +0000 (Fri, 20 Aug 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-26 12:03:00 +0000 (Thu, 26 Aug 2021)");

  script_cve_id("CVE-2021-37698");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Icinga 2.5.0 < 2.11.11, 2.12.0 < 2.12.6, 2.13.0 < 2.13.1 Certificate Validation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_icinga2_http_detect.nasl");
  script_mandatory_keys("icinga2/detected");

  script_tag(name:"summary", value:"Icinga 2 is prone to a TLS server certificate validation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Despite a CA is specified, none of ElasticsearchWriter,
  GelfWriter, InfluxdbWriter and Influxdb2Writer verify the server's certificate.");

  script_tag(name:"affected", value:"Icinga2 version 2.5.0 through 2.11.10, 2.12.0 through 2.12.5
  and 2.13.0.");

  script_tag(name:"solution", value:"Update to version 2.11.11, 2.12.6, 2.13.1 or later.");

  script_xref(name:"URL", value:"https://github.com/Icinga/icinga2/security/advisories/GHSA-cxfm-8j5v-5qr2");

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

if (version_in_range(version: version, test_version: "2.5.0", test_version2: "2.11.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.11.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.12.0", test_version2: "2.12.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.12.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version == "2.13.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.13.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
