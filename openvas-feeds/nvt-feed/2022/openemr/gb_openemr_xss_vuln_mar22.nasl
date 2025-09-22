# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:open-emr:openemr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124053");
  script_version("2025-04-11T15:45:04+0000");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2022-04-05 18:04:08 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-04 19:52:00 +0000 (Mon, 04 Apr 2022)");

  script_cve_id("CVE-2022-1181");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenEMR <= 6.0.0.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_openemr_http_detect.nasl");
  script_mandatory_keys("openemr/detected");

  script_tag(name:"summary", value:"OpenEMR is prone to an cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"OpenEMR version 6.0.0.2 and prior.");

  script_tag(name:"solution", value:"Update to version 6.0.0.2 or later.");

  script_xref(name:"URL", value:"https://github.com/openemr/openemr/commit/2835cc397610fc28037302dad948c38fda032022");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/2534e0fb-f503-4a4b-aed1-ec448c98bf60");

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

if (version_is_less_equal(version: version, test_version: "6.0.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
