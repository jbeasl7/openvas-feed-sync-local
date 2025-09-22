# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ckeditor:ckeditor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152935");
  script_version("2024-11-26T07:35:52+0000");
  script_tag(name:"last_modification", value:"2024-11-26 07:35:52 +0000 (Tue, 26 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-08-22 04:13:50 +0000 (Thu, 22 Aug 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-23 16:20:42 +0000 (Fri, 23 Aug 2024)");

  script_cve_id("CVE-2024-43407", "CVE-2024-43411");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CKEditor 4.x < 4.25.0 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_ckeditor_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ckeditor/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"CKEditor 4 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-43407: Reflected cross-site scripting (XSS) in Code Snippet GeSHi plugin

  - CVE-2024-43411: Low-risk cross-site scripting (XSS) linked to potential domain takeover");

  script_tag(name:"affected", value:"CKEditor version 4.x prior to 4.25.0.");

  script_tag(name:"solution", value:"Update to version 4.25 or later.");

  script_xref(name:"URL", value:"https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-7r32-vfj5-c2jv");
  script_xref(name:"URL", value:"https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-6v96-m24v-f58j");

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

if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "4.25.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.25.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
