# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148032");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-05-03 07:00:23 +0000 (Tue, 03 May 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-03 18:19:00 +0000 (Mon, 03 Apr 2023)");

  script_cve_id("CVE-2021-31439", "CVE-2022-23121", "CVE-2022-23123", "CVE-2022-23122",
                "CVE-2022-23125", "CVE-2022-23124", "CVE-2022-0194");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Multiple Vulnerabilities (QSA-22-12)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Upon the latest release of Netatalk 3.1.13, the Netatalk
  development team disclosed multiple fixed vulnerabilities affecting earlier versions of the
  software.");

  script_tag(name:"affected", value:"QNAP QTS version 4.2.6 prior to 4.2.6 build 20220623, 4.3.x prior
  to 4.3.3.2057 build 20220623, 4.3.4.x prior to 4.3.4.2107 build 20220712, 4.3.5.x prior to 4.3.6.2050
  build 20220526, 4.4.x prior to 4.5.4.2012 build 20220419, 5.0.0.x prior to 5.0.0.2055 build 20220531
  and 5.0.1.x prior to 5.0.1.2034 build 20220515.");

  script_tag(name:"solution", value:"Update to version 4.2.6 build 20220623, 4.3.3.2057 build 20220623,
  4.3.4.2107 build 20220712, 4.3.6.2050 build 20220526, 4.5.4.2012 build 20220419, 5.0.0.2055 build
  20220531, 5.0.1.2034 build 20220515 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-22-12");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version_is_less(version: version, test_version: "4.2.6")) {
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20220623");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.2.6") &&
   (!build || version_is_less(version: build, test_version: "20220623"))) {
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20220623");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^4\.3\.[0123]") {
  if (version_is_less(version: version, test_version: "4.3.3.2057")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3.2057", fixed_build: "20220623");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.3.3.2057") &&
     (!build || version_is_less(version: build, test_version: "20220623"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3.2057", fixed_build: "20220623");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^4\.3\.4") {
  if (version_is_less(version: version, test_version: "4.3.4.2107")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.4.2107", fixed_build: "20220712");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.3.4.2107") &&
     (!build || version_is_less(version: build, test_version: "20220712"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.4.2107", fixed_build: "20220712");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^4\.3\.[56]") {
  if (version_is_less(version: version, test_version: "4.3.6.2050")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.6.2050", fixed_build: "20220526");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.3.6.2050") &&
     (!build || version_is_less(version: build, test_version: "20220526"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.6.2050", fixed_build: "20220526");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^4\.[45]") {
  if (version_is_less(version: version, test_version: "4.5.4.2012")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.5.4.2012", fixed_build: "20220419");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.5.4.2012") &&
     (!build || version_is_less(version: build, test_version: "20220419"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.5.4.2012", fixed_build: "20220419");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^5\.0\.0") {
  if (version_is_less(version: version, test_version: "5.0.0.2055")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "5.0.0.2055", fixed_build: "20220531");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "5.0.0.2055") &&
     (!build || version_is_less(version: build, test_version: "20220531"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "5.0.0.2055", fixed_build: "20220531");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^5\.0\.1") {
  if (version_is_less(version: version, test_version: "5.0.1.2034")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "5.0.1.2034", fixed_build: "20220515");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "5.0.1.2034") &&
     (!build || version_is_less(version: build, test_version: "20220515"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "5.0.1.2034", fixed_build: "20220515");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
