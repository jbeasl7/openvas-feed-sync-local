# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:managewp:broken_link_checker";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127177");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2022-09-07 11:49:42 +0000 (Wed, 07 Sep 2022)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-10 02:00:00 +0000 (Sat, 10 Sep 2022)");

  script_cve_id("CVE-2022-2438");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Broken Link Checker Plugin < 1.11.17 PHAR Deserialization Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/broken-link-checker/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Broken Link Checker' is prone to an
  authenticated PHAR deserialisation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Deserialization of untrusted input via the '$log_file' value
  makes it possible for authenticated attackers with administrative privileges and above to call
  files using a PHAR wrapper that will deserialize the data and call arbitrary PHP Objects that can
  be used to perform a variety of malicious actions granted a POP chain is also present. It
  requires that the attacker is successful in uploading a file with the serialized payload.");

  script_tag(name:"affected", value:"WordPress Broken Link Checker plugin prior to version 1.11.17.");

  script_tag(name:"solution", value:"Update to version 1.11.17 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/vulnerability-advisories/#CVE-2022-2438");

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

if (version_is_less(version: version, test_version: "1.11.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.11.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
