# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143222");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2019-12-05 04:19:49 +0000 (Thu, 05 Dec 2019)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-06 19:14:00 +0000 (Fri, 06 Dec 2019)");

  script_cve_id("CVE-2019-7197");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS XSS Vulnerability (NAS-201911-26)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to a stored cross-site scripting vulnerability
  in QTS Event Notification.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A stored cross-site scripting (XSS) vulnerability has been
  reported to affect multiple versions of QTS. If exploited, this vulnerability may allow an attacker
  to inject and execute scripts on the administrator console.");

  script_tag(name:"affected", value:"QNAP QTS versions 4.2.6, 4.3.3, 4.3.4, 4.3.6 and 4.4.1.");

  script_tag(name:"solution", value:"Update to version 4.2.6 build 20190921, 4.3.3 build 20190921,
  4.3.4 build 20190921, 4.3.6 build 20190919, 4.4.1 build 20190918 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/nas-201911-26");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version_is_less(version: version, test_version: "4.2.6")) {
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20190921");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.2.6") &&
    (!build || version_is_less(version: build, test_version: "20190921"))) {
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20190921");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^4\.3\.[0123]") {
  if (version_is_less(version: version, test_version: "4.3.3")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3", fixed_build: "20190921");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.3.3") &&
     (!build || version_is_less(version: build, test_version: "20190921"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3", fixed_build: "20190921");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^4\.3\.4") {
  if (!build || version_is_less(version: build, test_version: "20190921")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.4", fixed_build: "20190921");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^4\.3\.[56]") {
  if (version_is_less(version: version, test_version: "4.3.6")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.6", fixed_build: "20190919");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.3.6") &&
     (!build || version_is_less(version: build, test_version: "20190919"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.6", fixed_build: "20190919");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^4\.4") {
  if (version_is_less(version: version, test_version: "4.4.1")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.4.1", fixed_build: "20190918");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.4.1") &&
     (!build || version_is_less(version: build, test_version: "20190918"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.4.1", fixed_build: "20190918");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
