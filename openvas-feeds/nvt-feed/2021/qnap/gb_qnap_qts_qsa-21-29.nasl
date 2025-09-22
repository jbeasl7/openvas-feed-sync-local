# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117527");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2021-07-01 13:24:22 +0000 (Thu, 01 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-06 17:56:00 +0000 (Tue, 06 Jul 2021)");

  script_cve_id("CVE-2021-28802", "CVE-2021-28804");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Multiple Command Injection Vulnerabilities (QSA-21-29)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple command injection
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple command injection vulnerabilities have been reported to
  affect QTS. If exploited, this vulnerability allows attackers to execute arbitrary commands in a
  compromised application.");

  script_tag(name:"affected", value:"QNAP NAS QTS prior version 4.5.1.1540 build 20210107.");

  script_tag(name:"solution", value:"Update to version 4.5.1.1540 build 20210107 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/QSA-21-29");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version_is_less(version: version, test_version: "4.5.1.1540")) {
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.5.1.1540", fixed_build: "20210107");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.5.1.1540") &&
          (!build || version_is_less(version: build, test_version: "20210107"))) {
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.5.1.1540", fixed_build: "20210107");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
