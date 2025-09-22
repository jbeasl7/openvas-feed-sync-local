# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146013");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2021-05-26 03:07:31 +0000 (Wed, 26 May 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-03 18:05:00 +0000 (Thu, 03 Jun 2021)");

  script_cve_id("CVE-2021-28798");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Directory Traversal Vulnerability (QSA-21-14)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A relative path traversal vulnerability has been reported to
  affect QNAP NAS running QTS. If exploited, this vulnerability allows attackers to modify files
  that impact system integrity.");

  script_tag(name:"affected", value:"QNAP NAS QTS prior version 4.3.3.1624 Build 20210416,
  4.3.6.1663 Build 20210504 and 4.5.2.1630 Build 20210406.");

  script_tag(name:"solution", value:"Update to version 4.3.3.1624 Build 20210416,
  4.3.6.1663 Build 20210504, 4.5.2.1630 Build 20210406 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-21-14");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

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

if(version =~ "^4\.3\.[456]") {
  if(version_is_less(version: version, test_version: "4.3.6.1663")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.6.1663", fixed_build: "20210504");
    security_message(port: 0, data: report);
    exit(0);
  }

  if(version_is_equal(version: version, test_version: "4.3.6.1663") &&
            (!build || version_is_less(version: build, test_version: "20210504"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.6.1663", fixed_build: "20210504");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if(version =~ "^4\.[45]") {
  if(version_is_less(version: version, test_version: "4.5.2.1630")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.5.2.1630", fixed_build: "20210406");
    security_message(port: 0, data: report);
    exit(0);
  }

  if(version_is_equal(version: version, test_version: "4.5.2.1630") &&
            (!build || version_is_less(version: build, test_version: "20210406"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.5.2.1630", fixed_build: "20210406");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
