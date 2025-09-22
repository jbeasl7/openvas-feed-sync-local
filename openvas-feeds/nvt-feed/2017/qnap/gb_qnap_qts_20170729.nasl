# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140260");
  script_version("2023-09-28T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-09-28 05:05:04 +0000 (Thu, 28 Sep 2023)");
  script_tag(name:"creation_date", value:"2017-08-01 10:17:13 +0700 (Tue, 01 Aug 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");

  script_cve_id("CVE-2017-11103", "CVE-2017-1000364");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS < 4.2.6 build 20170729, 4.3.x < 4.3.3 build 20170727 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"QNAP QTS is prone to multiple vulnerabilities:

  - Multiple vulnerabilities regarding OpenVPN.

  - Vulnerability in ActiveX controls that could allow for arbitrary code execution on the web client.

  - XSS vulnerability in Storage Manager and Backup Station.

  - CVE-2017-11103: 'Orpheus' Lyre' vulnerability in Samba that could be exploited to bypass
  authentication mechanisms.

  - CVE-2017-1000364: Vulnerability in the Linux kernel that could be exploited to circumvent the
  stack guard page.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"QNAP QTS version prior to 4.2.6 build 20170729 and 4.3.x prior
  to 4.3.3.0262 build 20170727.");

  script_tag(name:"solution", value:"Update to version 4.2.6 build 20170729, 4.3.3.0262 build 20170727
  or later.");

  script_xref(name:"URL", value:"https://www.techwarrant.com/firmware-update-qnap-ts-xx0-xx2-xx3-xx9-4-3-3-0262-build-20170727/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version_is_less(version: version, test_version: "4.2.6")) {
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20170729");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.2.6") &&
          (!build || version_is_less(version: build, test_version: "20170729"))) {
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20170729");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^4\.3\.") {
  if (version_is_less(version: version, test_version: "4.3.3.0262")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3.0262", fixed_build: "20170727");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.3.3.0262") &&
            (!build || version_is_less(version: build, test_version: "20170727"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3.0262", fixed_build: "20170727");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
