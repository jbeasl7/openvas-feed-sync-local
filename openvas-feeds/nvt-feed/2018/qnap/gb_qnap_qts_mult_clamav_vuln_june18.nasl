# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813520");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2018-06-11 17:13:13 +0530 (Mon, 11 Jun 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-12374", "CVE-2017-12375", "CVE-2017-12376", "CVE-2017-12377",
                "CVE-2017-12378", "CVE-2017-12379", "CVE-2017-12380");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Multiple ClamAV Vulnerabilities (NAS-201805-23)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple ClamAV vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A lack of input validation checking mechanisms during certain mail parsing operations and
    functions.

  - An improper input validation checking mechanisms when handling Portable Document Format (.pdf)
    files sent to an affected device.

  - An improper input validation checking mechanisms in mew packet files sent to an affected device.

  - An improper input validation checking mechanisms of '.tar' (Tape Archive) files sent to an
    affected device.

  - An improper input validation checking mechanisms in the message parsing function on an affected
    system.

  - An improper input validation checking mechanisms during certain mail parsing functions of the
    ClamAV software.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to launch
  denial of service (DoS) attacks or run arbitrary code on the NAS.");

  script_tag(name:"affected", value:"QNAP QTS version 4.2.6 through 4.2.6 build 20171208,
  4.3.3 through 4.3.3 build 20180126 and 4.3.4 through 4.3.4 build 20180323.");

  script_tag(name:"solution", value:"Update to QNAP QTS 4.2.6 build 20180504, 4.3.3 build 20180402,
  4.3.4 build 20180413 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en-us/security-advisory/nas-201805-23");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version =~ "^4\.2\.6") {
  if (version_is_less(version: version, test_version: "4.2.6")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20180504");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.2.6") &&
     (!build || version_is_less(version: build, test_version: "20180504"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20180504");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^4\.3\.[0123]") {
  if (version_is_less(version: version, test_version: "4.3.3")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3", fixed_build: "20180402");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.3.3") &&
     (!build || version_is_less(version: build, test_version: "20180402"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3", fixed_build: "20180402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^4\.3\.4") {
  if (version_is_less(version: version, test_version: "4.3.4")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.4", fixed_build: "20180413");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.3.4") &&
     (!build || version_is_less(version: build, test_version: "20180413"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.4", fixed_build: "20180413");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
