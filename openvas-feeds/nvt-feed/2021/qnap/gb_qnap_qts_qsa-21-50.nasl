# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147195");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2021-11-23 03:31:20 +0000 (Tue, 23 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS RCE Vulnerability (QSA-21-50)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A heap-based buffer overflow vulnerability has been reported to
  affect QNAP NAS devices that have Apple File Protocol (AFP) enabled in QTS. If exploited, this
  vulnerability allows attackers to execute arbitrary code.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-21-50");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version_is_less(version: version, test_version: "4.3.3.1799")) {
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3.1799", fixed_build: "20211008");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.3.3.1799") &&
   (!build || version_is_less(version: build, test_version: "20211008"))) {
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3.1799", fixed_build: "20211008");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^4\.3\.[456]") {
  if (version_is_less(version: version, test_version: "4.3.6.1831")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.6.1831", fixed_build: "20211019");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.3.6.1831") &&
     (!build || version_is_less(version: build, test_version: "20211019"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.6.1831", fixed_build: "20211019");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^4\.[45]") {
  if (version_is_less(version: version, test_version: "4.5.4.1800")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.5.4.1800", fixed_build: "20210923");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.5.4.1800") &&
     (!build || version_is_less(version: build, test_version: "20210923"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.5.4.1800", fixed_build: "20210923");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^5\.") {
  if (version_is_less(version: version, test_version: "5.0.0.1808")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "5.0.0.1808", fixed_build: "20211001");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "5.0.0.1808") &&
     (!build || version_is_less(version: build, test_version: "20211001"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "5.0.0.1808", fixed_build: "20211001");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
