# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107274");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2017-12-13 13:24:30 +0100 (Wed, 13 Dec 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-04 18:45:00 +0000 (Thu, 04 Jan 2018)");

  script_cve_id("CVE-2017-17027", "CVE-2017-17028", "CVE-2017-17029", "CVE-2017-17030",
                "CVE-2017-17031", "CVE-2017-17032", "CVE-2017-17033", "CVE-2017-14746",
                "CVE-2017-15275");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS < 4.2.6 build 20171208, 4.3.3.x < 4.3.3.0396 build 20171205, 4.3.4.x < 4.3.4.0411 build 20171208 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is vulnerable to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2017-17027: Buffer overflow in FTP service

  - CVE-2017-17028: Buffer overflow in external device function

  - CVE-2017-17029, CVE-2017-17030: Buffer overflow in login function

  - CVE-2017-17031, CVE-2017-17032, CVE-2017-17033: Buffer overflow in password function

  - CVE-2017-15275: Heap memory leak in Samba

  - CVE-2017-14746: Use-after-free in Samba");

  script_tag(name:"impact", value:"It is possible to overflow a stack buffer with a specially crafted
  HTTP request and hijack the control flow to achieve arbitrary code execution.");

  script_tag(name:"affected", value:"QNAP QTS version 4.2.x prior to 4.2.6 build 20171208, 4.3.x prior
  to 4.3.3.0396 build 20171205 and 4.3.4.x prior to 4.3.4.0411 build 20171208.");

  script_tag(name:"solution", value:"Update to version 4.2.6 build 20171208, 4.3.3.0396 build 20171205,
  4.3.4.0411 build 20171208 or later.");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3565");
  script_xref(name:"URL", value:"https://www.qnapclub.cz/forum/viewtopic.php?t=263844");
  script_xref(name:"URL", value:"https://www.techwarrant.com/firmware-update-qnap-qts-4-3-3-0396-build-20171205/");
  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/nas-201712-15");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version =~ "^4\.2") {
  if (version_is_less(version: version, test_version: "4.2.6")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20171208");
    security_message(port: 0, data: report);
    exit(0);
  } else if (version_is_equal(version: version, test_version: "4.2.6") &&
            (!build || version_is_less(version: build, test_version: "20171208"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20171208");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^4\.3\.[0123]") {
  if (version_is_less(version: version, test_version: "4.3.3.0396")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3.0396", fixed_build: "20171205");
    security_message(port: 0, data: report);
    exit(0);
  } else if (version_is_equal(version: version, test_version: "4.3.3.0396") &&
            (!build || version_is_less(version: build, test_version:"20171205"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3.0396", fixed_build: "20171205");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^4\.3\.4") {
  if (version_is_less(version: version, test_version: "4.3.4.0411")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.4.0411", fixed_build: "20171208");
    security_message(port: 0, data: report);
    exit(0);
  } else if (version_is_equal(version: version, test_version: "4.3.4.0411") &&
            (!build || version_is_less(version: build, test_version:"20171208"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.4.0411", fixed_build: "20171208");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
