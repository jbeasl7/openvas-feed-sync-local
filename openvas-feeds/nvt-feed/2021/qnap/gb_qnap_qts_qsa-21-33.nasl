# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146650");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2021-09-13 08:58:04 +0000 (Mon, 13 Sep 2021)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-23 17:26:00 +0000 (Thu, 23 Sep 2021)");

  script_cve_id("CVE-2021-28816", "CVE-2021-34343");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Buffer Overflow Vulnerabilities (QSA-21-33)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple buffer overflow vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Two stack buffer overflow vulnerabilities have been reported to
  affect QNAP devices running QTS. If exploited, these vulnerabilities allow attackers to execute
  arbitrary code.");

  script_tag(name:"affected", value:"QNAP NAS QTS prior versions 4.3.3.1693 build 20210624,
  4.3.6.1750 build 20210730, 4.5.4.1715 build 20210630 and 5.0.0.1716 build 20210701.");

  script_tag(name:"solution", value:"Update to version 4.3.3.1693 build 20210624,
  4.3.6.1750 build 20210730, 4.5.4.1715 build 20210630, 5.0.0.1716 build 20210701 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-21-33");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version_is_less(version: version, test_version: "4.3.3.1693")) {
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3.1693", fixed_build: "20210624");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.3.3.1693") &&
   (!build || version_is_less(version: build, test_version: "20210624"))) {
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3.1693", fixed_build: "20210624");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^4\.3\.[456]") {
  if (version_is_less(version: version, test_version: "4.3.6.1750")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.6.1750", fixed_build: "20210730");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.3.6.1750") &&
     (!build || version_is_less(version: build, test_version: "20210730"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.6.1750", fixed_build: "20210730");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^4\.[45]") {
  if (version_is_less(version: version, test_version: "4.5.4.1715")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.5.4.1715", fixed_build: "20210630");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.5.4.1715") &&
     (!build || version_is_less(version: build, test_version: "20210630"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.5.4.1715", fixed_build: "20210630");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^5\.") {
  if (version_is_less(version: version, test_version: "5.0.0.1716")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "5.0.0.1716", fixed_build: "20210701");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "5.0.0.1716") &&
     (!build || version_is_less(version: build, test_version: "20210701"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "5.0.0.1716", fixed_build: "20210701");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
