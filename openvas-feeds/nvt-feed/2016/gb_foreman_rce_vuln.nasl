# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:theforeman:foreman";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106423");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2016-11-29 08:20:28 +0700 (Tue, 29 Nov 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");

  script_cve_id("CVE-2016-3728");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Foreman 0.2 < 1.10.4, 1.11.x < 1.11.2 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_foreman_http_detect.nasl");
  script_mandatory_keys("foreman/detected");

  script_tag(name:"summary", value:"Foreman is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The smart proxy TFTP API is vulnerable to arbitrary remote
  code execution, as it passes untrusted user input (the PXE template type) to the eval() function
  causing it to be executed.");

  script_tag(name:"affected", value:"Foreman version 0.2 prior to 1.10.4 and 1.11.x prior to
  1.11.2.");

  script_tag(name:"solution", value:"Update to version 1.10.4, 1.11.2 or later.");

  script_xref(name:"URL", value:"https://theforeman.org/security.html#2016-3728");

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

if (version_in_range_exclusive(version: version, test_version_lo: "0.2", test_version_up: "1.10.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.10.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.11.0", test_version_up: "1.11.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.11.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
