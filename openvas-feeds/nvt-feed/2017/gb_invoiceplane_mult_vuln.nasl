# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:invoiceplane:invoiceplane";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106832");
  script_version("2025-04-07T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-04-07 05:39:52 +0000 (Mon, 07 Apr 2025)");
  script_tag(name:"creation_date", value:"2017-05-26 12:18:19 +0700 (Fri, 26 May 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-30 19:15:34 +0000 (Thu, 30 Nov 2017)");

  script_cve_id("CVE-2017-1000238", "CVE-2017-1000239");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("InvoicePlane Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_invoiceplane_http_detect.nasl");
  script_mandatory_keys("invoiceplane/detected");

  script_tag(name:"summary", value:"InvoicePlane is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"InvoicePlane is prone to multiple vulnerabilities:

  - CVE-2017-1000238: Arbitrary file upload

  - CVE-2017-1000239: Stored cross-site scripting (XSS)");

  script_tag(name:"impact", value:"An authenticated attacker may compromise the web server.
  Potentially sensitive invoice data might get exposed through this attack.");

  script_tag(name:"affected", value:"InvoicePlane prior to version 1.5.2.");

  script_tag(name:"solution", value:"Update to version 1.5.2 or later.");

  script_xref(name:"URL", value:"https://sec-consult.com/vulnerability-lab/advisory/arbitrary-file-upload-stored-xss/");

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

if (version_is_less(version: version, test_version: "1.5.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.5.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
