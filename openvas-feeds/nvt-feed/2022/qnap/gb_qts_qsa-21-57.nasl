# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147645");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2022-02-17 03:21:27 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS RCE Vulnerability (QSA-21-57)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The vulnerability allows attackers to run arbitrary code in the
  system.");

  script_tag(name:"affected", value:"QNAP QTS version 4.5.3 and later.");

  script_tag(name:"solution", value:"Update to version 4.5.4.1892 build 20211223, 5.0.0.1891 build
  20211221 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-21-57");
  script_xref(name:"URL", value:"https://www.qnap.com/en/release-notes/qts/4.5.4.1892/20211223");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version =~ "^4\.5") {
  if (version_in_range_exclusive(version: version, test_version_lo: "4.5.3", test_version_up:"4.5.4.1892")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.5.4.1892", fixed_build: "20211223");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.5.4.1892") &&
     (!build || version_is_less(version: build, test_version: "20211223"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.5.4.1892", fixed_build: "20211223");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^5") {
  if (version_is_less(version: version, test_version: "5.0.0.1891")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "5.0.0.1891", fixed_build: "20211221");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "5.0.0.1891") &&
     (!build || version_is_less(version: build, test_version: "20211221"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "5.0.0.1891", fixed_build: "20211221");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
