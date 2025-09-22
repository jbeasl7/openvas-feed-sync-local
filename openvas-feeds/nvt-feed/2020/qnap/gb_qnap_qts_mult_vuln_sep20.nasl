# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144533");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2020-09-08 02:11:20 +0000 (Tue, 08 Sep 2020)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-21 23:15:00 +0000 (Fri, 21 Feb 2020)");

  script_cve_id("CVE-2017-7418", "CVE-2019-19269", "CVE-2019-19270", "CVE-2019-18217",
                "CVE-2019-19272", "CVE-2019-19271", "CVE-2020-9273", "CVE-2020-9272",
                "CVE-2020-10745");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Multiple ProFTPD Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple vulnerabilities in ProFTPD and other
  components.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2017-7418: Local security bypass in ProFTPD

  - CVE-2019-19269, CVE-2019-19272: Multiple NULL pointer dereferences in ProFTPD

  - CVE-2019-19270, CVE-2019-19271: Multiple improper certificate validations in ProFTPD

  - CVE-2019-18217: Denial of service vulnerability in ProFTPD

  - CVE-2020-9273: Use-after-free in ProFTPD that could be exploited for arbitrary code execution

  - CVE-2020-9272: Out-of-bounds read in ProFTPD

  - UDP flood denial-of-service in Samba Active Directory Domain Controller (AD DC)

  - CVE-2020-10745: Resource exhaustion in Samba Active Directory domain controller");

  script_tag(name:"affected", value:"QNAP QTS versions 4.2.6, 4.3.3, 4.3.4, 4.3.6 and 4.4.3.");

  script_tag(name:"solution", value:"Update to version 4.2.6 build 20200821, 4.3.3.1386 build
  20200821, 4.3.4.1417 build 20200821, 4.3.6.1411 Build 20200825, 4.4.3.1400 build 20200817
  or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/release-notes/qts/4.4.3.1400/20200817");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version_is_less(version: version, test_version: "4.2.6")) {
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20200821");
  security_message(port: 0, data: report);
  exit(0);
}

if(version_is_equal(version: version, test_version: "4.2.6") &&
   (!build || version_is_less(version: build, test_version: "20200821"))) {
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20200821");
  security_message(port: 0, data: report);
  exit(0);
}

if(version =~ "^4\.3\.[0123]") {
  if(version_is_less(version: version, test_version: "4.3.3.1386")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3.1386", fixed_build: "20200821");
    security_message(port: 0, data: report);
    exit(0);
  }

  if(version_is_equal(version: version, test_version: "4.3.3.1386") &&
     (!build || version_is_less(version: build, test_version: "20200821"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3.1386", fixed_build: "20200821");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if(version =~ "^4\.3\.4") {
  if(version_is_less(version: version, test_version: "4.3.4.1417")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.4.1417", fixed_build: "20200821");
    security_message(port: 0, data: report);
    exit(0);
  }

  if(version_is_equal(version: version, test_version: "4.3.4.1417") &&
     (!build || version_is_less(version: build, test_version: "20200821"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.4.1417", fixed_build: "20200821");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if(version =~ "^4\.3\.[56]") {
  if(version_is_less(version: version, test_version: "4.3.6.1411")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.6.1411", fixed_build: "20200825");
    security_message(port: 0, data: report);
    exit(0);
  }

  if(version_is_equal(version: version, test_version: "4.3.6.1411") &&
     (!build || version_is_less(version: build, test_version: "20200825"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.6.1411", fixed_build: "20200825");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if(version =~ "^4\.4") {
  if(version_is_less(version: version, test_version: "4.4.3.1400")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.4.3.1400", fixed_build: "20200817");
    security_message(port: 0, data: report);
    exit(0);
  }

  if(version_is_equal(version: version, test_version: "4.4.3.1400") &&
     (!build || version_is_less(version: build, test_version: "20200817"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.4.3.1400", fixed_build: "20200817");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
