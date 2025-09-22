# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ckeditor:ckeditor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125145");
  script_version("2025-02-25T13:24:30+0000");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-02-24 12:14:00 +0000 (Mon, 24 Feb 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2025-25299");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # since vulnerability occurrence depends on specific conditions

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CKEditor 41.3.0 - 44.2.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_ckeditor_http_detect.nasl");
  script_mandatory_keys("ckeditor/detected");

  script_tag(name:"summary", value:"CKEditor 5 is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A XSS vulnerability was identified in the CKEditor 5 real-time
  collaboration package. This vulnerability can lead to unauthorized JavaScript code execution and
  affects user markers, which represent users' positions within the document.

  Note: This affects only installations with Real-time collaborative editing enabled.");

  script_tag(name:"affected", value:"CKEditor versions 41.3.0 through 44.2.0.");

  script_tag(name:"solution", value:"Update to version 44.2.1 or later.");

  script_xref(name:"URL", value:"https://ckeditor.com/docs/ckeditor5/latest/features/collaboration/real-time-collaboration/real-time-collaboration.html");
  script_xref(name:"URL", value:"https://github.com/ckeditor/ckeditor5/releases/tag/v44.2.1");
  script_xref(name:"URL", value:"https://github.com/ckeditor/ckeditor5/security/advisories/GHSA-j3mm-wmfm-mwvh");

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

if (version_in_range_exclusive(version: version, test_version_lo: "41.3.0", test_version_up: "44.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "44.2.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
