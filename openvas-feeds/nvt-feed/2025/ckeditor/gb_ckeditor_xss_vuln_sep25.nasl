# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ckeditor:ckeditor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124907");
  script_version("2025-09-19T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-10 12:14:00 +0000 (Wed, 10 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2025-58064");

  # nb: Since vulnerability occurrence depends on specific editor configuration
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CKEditor 44.2.0 < 45.2.2, 46.0.0 < 46.0.3 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_ckeditor_http_detect.nasl");
  script_mandatory_keys("ckeditor/detected");

  script_tag(name:"summary", value:"CKEditor 5 is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An XSS vulnerability has been discovered in the CKEditor 5
  clipboard package. This vulnerability could be triggered by a specific user action, leading to
  unauthorized JavaScript code execution, if the attacker managed to insert a malicious content into
  the editor, which might happen with a very specific editor configuration.");

  script_tag(name:"affected", value:"CKEditor version 44.2.0 prior to 45.2.2 and 46.0.0 prior to
  46.0.3.

  Note: This vulnerability affects only installations where the editor configuration meets one of
  the following criteria:

  - HTML embed plugin is enabled

  - Custom plugin introducing editable element which implements view RawElement is enabled");

  script_tag(name:"solution", value:"Update to version 45.2.2, 46.0.3 or later.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-x9gp-vjh6-3wv6");

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

if (version_in_range_exclusive(version: version, test_version_lo: "44.2.0", test_version_up: "45.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "45.2.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "46.0.0", test_version_up: "46.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "46.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}


exit(99);
