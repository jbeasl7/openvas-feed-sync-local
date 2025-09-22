# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145023");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2020-12-11 03:57:42 +0000 (Fri, 11 Dec 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-22 21:00:00 +0000 (Tue, 22 Jun 2021)");

  script_cve_id("CVE-2020-2495", "CVE-2020-2496", "CVE-2020-2497", "CVE-2020-2498");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Multiple XSS Vulnerabilities (QSA-20-12)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Multiple XSS vulnerabilities in File Station, System Connection
  Logs and certificate configuration could allow remote attackers to inject malicious code.");

  script_tag(name:"affected", value:"QNAP QTS prior to versions 4.2.6 build 20200611, 4.3.3.1315 build
  20200611, 4.3.4.1368 build 20200703, 4.3.6.1333 build 20200608, 4.4.3.1354 build 20200702 and
  4.5.1.1456 build 20201015.");

  script_tag(name:"solution", value:"Update to version 4.2.6 build 20200611, 4.3.3.1315 build
  20200611, 4.3.4.1368 build 20200703, 4.3.6.1333 build 20200608, 4.4.3.1354 build 20200702,
  4.5.1.1456 build 20201015 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-20-12");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if(version_is_less(version: version, test_version: "4.2.6")) {
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20200611");
  security_message(port: 0, data: report);
  exit(0);
}

if(version_is_equal(version: version, test_version: "4.2.6") &&
   (!build || version_is_less(version: build, test_version: "20200611"))) {
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20200611");
  security_message(port: 0, data: report);
  exit(0);
}

if(version =~ "^4\.3\.[0123]") {
  if(version_is_less(version: version, test_version: "4.3.3.1315")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3.1315", fixed_build: "20200611");
    security_message(port: 0, data: report);
    exit(0);
  }

  if(version_is_equal(version: version, test_version: "4.3.3.1315") &&
     (!build || version_is_less(version: build, test_version: "20200611"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3.1315", fixed_build: "20200611");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if(version =~ "^4\.3\.4") {
  if(version_is_less(version: version, test_version: "4.3.4.1368")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.4.1368", fixed_build: "20200703");
    security_message(port: 0, data: report);
    exit(0);
  }

  if(version_is_equal(version: version, test_version: "4.3.4.1368") &&
     (!build || version_is_less(version: build, test_version: "20200703"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.4.1368", fixed_build: "20200703");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if(version =~ "^4\.3\.[56]") {
  if(version_is_less(version: version, test_version: "4.3.6.1333")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.6.1333", fixed_build: "20200608");
    security_message(port: 0, data: report);
    exit(0);
  }

  if(version_is_equal(version: version, test_version: "4.3.6.1333") &&
     (!build || version_is_less(version: build, test_version: "20200608"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.6.1333", fixed_build: "20200608");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if(version =~ "^4\.4") {
  if(version_is_less(version: version, test_version: "4.4.3.1354")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.4.3.1354", fixed_build: "20200702");
    security_message(port: 0, data: report);
    exit(0);
  }

  if(version_is_equal(version: version, test_version: "4.4.3.1354") &&
     (!build || version_is_less(version: build, test_version: "20200702"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.4.3.1354", fixed_build: "20200702");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if(version =~ "^4\.5") {
  if(version_is_less(version: version, test_version: "4.5.1.1456")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.5.1.1456", fixed_build: "20201015");
    security_message(port: 0, data: report);
    exit(0);
  }

  if(version_is_equal(version: version, test_version: "4.5.1.1456") &&
     (!build || version_is_less(version: build, test_version: "20201015"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.5.1.1456", fixed_build: "20201015");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
