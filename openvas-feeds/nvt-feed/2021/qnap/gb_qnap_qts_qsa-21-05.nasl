# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145776");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2021-04-19 04:03:36 +0000 (Mon, 19 Apr 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-21 16:56:00 +0000 (Mon, 21 Jun 2021)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-2509");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Command Injection Vulnerability (QSA-21-05)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to a command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A command injection vulnerability has been reported to affect QTS. If
  exploited, this vulnerability allows attackers to execute arbitrary commands in a compromised application.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-21-05");
  script_xref(name:"URL", value:"https://securingsam.com/new-vulnerabilities-allow-complete-takeover/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if(version_is_less(version: version, test_version: "4.2.6")) {
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20210327");
  security_message(port: 0, data: report);
  exit(0);
}

if(version_is_equal(version: version, test_version: "4.2.6") &&
          (!build || version_is_less(version: build, test_version: "20210327"))) {
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20210327");
  security_message(port: 0, data: report);
  exit(0);
}

if(version =~ "^4\.3") {
  if(version_is_less(version: version, test_version: "4.3.3.1624")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3.1624", fixed_build: "20210416");
    security_message(port: 0, data: report);
    exit(0);
  }

  if(version_is_equal(version: version, test_version: "4.3.3.1624") &&
            (!build || version_is_less(version: build, test_version: "20210416"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3.1624", fixed_build: "20210416");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if(version =~ "^4\.3\.4") {
  if(version_is_less(version: version, test_version: "4.3.4.1632")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.4.1632", fixed_build: "20210324");
    security_message(port: 0, data: report);
    exit(0);
  }

  if(version_is_equal(version: version, test_version: "4.3.4.1632") &&
            (!build || version_is_less(version: build, test_version: "20210324"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.4.1632", fixed_build: "20210324");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if(version =~ "^4\.3\.[56]") {
  if(version_is_less(version: version, test_version: "4.3.6.1620")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.6.1620", fixed_build: "20210322");
    security_message(port: 0, data: report);
    exit(0);
  }

  if(version_is_equal(version: version, test_version: "4.3.6.1620") &&
            (!build || version_is_less(version: build, test_version: "20210322"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.6.1620", fixed_build: "20210322");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if(version =~ "^4\.5\.1") {
  if(version_is_less(version: version, test_version: "4.5.1.1495")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.5.1.1495", fixed_build: "20201123");
    security_message(port: 0, data: report);
    exit(0);
  }

  if(version_is_equal(version: version, test_version: "4.5.1.1495") &&
            (!build || version_is_less(version: build, test_version: "20201123"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.5.1.1495", fixed_build: "20201123");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if(version =~ "^4\.5\.2") {
  if(version_is_less(version: version, test_version: "4.5.2.1566")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.5.2.1566", fixed_build: "20210202");
    security_message(port: 0, data: report);
    exit(0);
  }

  if(version_is_equal(version: version, test_version: "4.5.2.1566") &&
            (!build || version_is_less(version: build, test_version: "20210202"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.5.2.1566", fixed_build: "20210202");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
