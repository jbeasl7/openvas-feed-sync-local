# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152551");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-07-04 03:26:56 +0000 (Thu, 04 Jul 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-24 16:42:02 +0000 (Tue, 24 Sep 2024)");

  script_cve_id("CVE-2023-39300");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS OS Command Injection Vulnerability (QSA-24-26)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to an OS command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"If exploited, the vulnerability could allow remote attackers to
  execute arbitrary commands on the operating system through an application's input.");

  script_tag(name:"affected", value:"QNAP QTS versions 4.2.x and 4.3.x.");

  script_tag(name:"solution", value:"Update to version 4.2.6 build 20240618, 4.3.3.2784 build
  20240619, 4.3.4.2814 build 20240618, 4.3.6.2805 build 20240619 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-24-26");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version =~ "^4\.2\.[0-6]") {
  if (version_is_less(version: version, test_version:"4.2.6")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "4.2.6", fixed_build: "20240618");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.2.6") &&
     (!build || version_is_less(version: build, test_version: "20240618"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "4.2.6", fixed_build: "20240618");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^4\.3\.[0-3]") {
  if (version_is_less(version: version, test_version: "4.3.3.2784")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "4.3.3.2784", fixed_build: "20240619");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.3.3.2784") &&
      (!build || version_is_less(version: build, test_version: "20240619"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "4.3.3.2784", fixed_build: "20240619");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^4\.3\.4") {
  if (version_is_less(version: version, test_version: "4.3.4.2814")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "4.3.4.2814", fixed_build: "20240618");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.3.4.2814") &&
      (!build || version_is_less(version: build, test_version: "20240618"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "4.3.4.2814", fixed_build: "20240618");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^4\.3\.[56]") {
  if (version_is_less(version: version, test_version: "4.3.6.2805")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "4.3.6.2805", fixed_build: "20240619");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.3.6.2805") &&
      (!build || version_is_less(version: build, test_version: "20240619"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "4.3.6.2805", fixed_build: "20240619");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
