# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:quts_hero";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131372");
  script_version("2025-05-08T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-08 05:40:19 +0000 (Thu, 08 May 2025)");
  script_tag(name:"creation_date", value:"2025-01-02 10:19:56 +0000 (Thu, 02 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2022-27600");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTS hero DoS Vulnerability (QSA-23-09)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/quts_hero/detected");

  script_tag(name:"summary", value:"QNAP QuTS hero is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An uncontrolled resource consumption can allow remote users to
  launch a denial-of-service (DoS) attack.");

  script_tag(name:"affected", value:"QNAP QuTS hero version h4.5.x prior to h4.5.4.2374 and h5.0.x
  prior to h5.0.1.2277.");

  script_tag(name:"solution", value:"Update to version h4.5.4.2374 build 20230417, h5.0.1.2277
  build 20230112 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-09");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/quts_hero/build");

if (version =~ "^h4\.5") {
  if (version_is_less(version: version, test_version: "h4.5.4.2374")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h4.5.4.2374", fixed_build: "20241120");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "h4.5.4.2374") &&
     (!build || version_is_less(version: build, test_version: "20241120"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h4.5.4.2374", fixed_build: "20241120");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^h5\.0") {
  if (version_is_less(version: version, test_version: "h5.0.1.2277")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.0.1.2277", fixed_build: "20241116");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "h5.0.1.2277") &&
     (!build || version_is_less(version: build, test_version: "20241116"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.0.1.2277", fixed_build: "20241116");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
