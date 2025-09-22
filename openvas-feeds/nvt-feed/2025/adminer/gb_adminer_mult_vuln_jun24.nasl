# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adminer:adminer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.119086");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-01 12:29:13 +0000 (Mon, 01 Sep 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-24 19:11:50 +0000 (Mon, 24 Jun 2024)");

  script_cve_id("CVE-2023-45195", "CVE-2023-45196", "CVE-2023-45197");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Adminer < 4.16.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_adminer_http_detect.nasl");
  script_mandatory_keys("adminer/detected");

  script_tag(name:"summary", value:"Adminer is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-45195: Server-side request forgery (SSRF) vulnerability

  - CVE-2023-45196: Denial-of-service (DoS) vulnerability

  - CVE-2023-45197: File upload vulnerability");

  script_tag(name:"affected", value:"Adminer versions prior to 4.16.0.");

  script_tag(name:"solution", value:"Update to version 4.16.0 or later.");

  script_xref(name:"URL", value:"https://github.com/vrana/adminer/issues/1149");
  script_xref(name:"URL", value:"https://github.com/vrana/adminer/commit/578c9fca923e3afeccb29761f5da37dfe5d60993");
  script_xref(name:"URL", value:"https://github.com/vrana/adminer/commit/b2759df1f949f24e69737e7d1151551afc8dd37e");
  script_xref(name:"URL", value:"https://github.com/vrana/adminer/commit/d94e348f57571c52bd58a5c0ee28ef588aaa5c45");

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

if (version_is_less(version: version, test_version: "4.16.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.16.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
