# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ckeditor:ckeditor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124695");
  script_version("2024-10-03T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-10-03 05:05:33 +0000 (Thu, 03 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-09-30 08:00:19 +0000 (Mon, 30 Sep 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-01 16:26:48 +0000 (Tue, 01 Oct 2024)");

  script_cve_id("CVE-2024-45613");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # since vulnerability occurrence depends on specific conditions

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CKEditor 40.x < 43.1.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_ckeditor_http_detect.nasl");
  script_mandatory_keys("ckeditor/detected");

  script_tag(name:"summary", value:"CKEditor 5 is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"This vulnerability could be triggered by a specific user action,
  leading to unauthorized JavaScript code execution, if the attacker managed to insert a malicious
  content into the editor, which might happen with a very specific editor configuration.

  Note: This affects only installations where the editor configuration meets the
  following criteria: The Block Toolbar plugin is enabled and one of the following plugins is also
  enabled: General HTML Support with a configuration that permits unsafe markup or HTML Embed.");

  script_tag(name:"affected", value:"CKEditor version 40.x prior to 43.1.1.");

  script_tag(name:"solution", value:"Update to version 43.1.1 or later.");

  script_xref(name:"URL", value:"https://github.com/ckeditor/ckeditor5/security/advisories/GHSA-rgg8-g5x8-wr9v");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "40.0", test_version_up: "43.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "43.1.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
