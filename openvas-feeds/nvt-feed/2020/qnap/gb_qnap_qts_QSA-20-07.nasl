# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144825");
  script_version("2024-01-05T16:09:35+0000");
  script_tag(name:"last_modification", value:"2024-01-05 16:09:35 +0000 (Fri, 05 Jan 2024)");
  script_tag(name:"creation_date", value:"2020-10-26 06:34:20 +0000 (Mon, 26 Oct 2020)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-04 02:15:00 +0000 (Thu, 04 Jan 2024)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-1472");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Zerologon Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to the Zerologon vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If exploited, this elevation of privilege vulnerability allows
  remote attackers to bypass security measures via a compromised QTS device on the network. The NAS
  may be exposed to this vulnerability if users have configured the device as a domain controller in
  Control Panel > Network & File Services > Win/Mac/NFS > Microsoft Networking.");

  # nb: Advisory states that "QTS 2.x and QES are not affected by this vulnerability." thus we can concluded QTS 3.x is also affected
  script_tag(name:"affected", value:"QNAP QTS versions 3.x, 4.3.3, 4.3.4, 4.3.6, 4.4.3 and 4.5.1.");

  script_tag(name:"solution", value:"Update to version 4.3.3.1432 build 20201006, 4.3.4.1463
  build 20201006, 4.3.6.1446 Build 20200929, 4.4.3.1439 build 20200925, 4.5.1.1456 build 20201015
  or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-20-07");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version =~ "^[34]") {
  if (version_is_less(version: version, test_version: "4.3.3.1432")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3.1432", fixed_build: "20201006");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.3.3.1432") &&
            (!build || version_is_less(version: build, test_version: "20201006"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3.1432", fixed_build: "20201006");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^4\.3\.4") {
  if (version_is_less(version: version, test_version: "4.3.4.1463")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.4.1463", fixed_build: "20201006");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.3.4.1463") &&
            (!build || version_is_less(version: build, test_version: "20201006"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.4.1463", fixed_build: "20201006");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^4\.3\.[56]") {
  if (version_is_less(version: version, test_version: "4.3.6.1446")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.6.1446", fixed_build: "20200929");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.3.6.1446") &&
            (!build || version_is_less(version: build, test_version: "20200929"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.6.1446", fixed_build: "20200929");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^4\.4") {
  if (version_is_less(version: version, test_version: "4.4.3.1439")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.4.3.1439", fixed_build: "20200925");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.4.3.1439") &&
            (!build || version_is_less(version: build, test_version: "20200925"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.4.3.1439", fixed_build: "20200925");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^4\.5") {
  if (version_is_less(version: version, test_version: "4.5.1.1456")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.5.1.1456", fixed_build: "20201015");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.5.1.1456") &&
            (!build || version_is_less(version: build, test_version: "20201015"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.5.1.1456", fixed_build: "20201015");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
