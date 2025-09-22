# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149471");
  script_version("2023-10-13T05:06:10+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-03-31 03:54:16 +0000 (Fri, 31 Mar 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-05 20:28:00 +0000 (Thu, 05 Jan 2023)");

  script_cve_id("CVE-2023-0286", "CVE-2022-4304", "CVE-2023-0215", "CVE-2022-4450",
                "CVE-2023-22809", "CVE-2023-23355", "CVE-2022-27597", "CVE-2022-27598",
                "CVE-2022-42898", "CVE-2022-3437", "CVE-2022-3592");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Multiple Vulnerabilities (QSA-23-02, QSA-23-03, QSA-23-06, QSA-23-10, QSA-23-11, QSA-23-15)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-0286, CVE-2022-4304, CVE-2023-0215, CVE-2022-4450: Multiple OpenSSL vulnerabilities

  - CVE-2023-22809: Vulnerability in sudo

  - CVE-2023-23355: Authenticated remote code execution (RCE)

  - CVE-2022-27597, CVE-2022-27598: Authenticated information disclosure

  - CVE-2022-42898: Buffer overflow in Samba

  - CVE-2022-3437, CVE-2022-3592: Multiple buffer overflows in Samba");

  script_tag(name:"affected", value:"QNAP QTS version 5.0.1.");

  script_tag(name:"solution", value:"Update to version 5.0.1.2234 build 20230322 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-02");
  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-03");
  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-06");
  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-10");
  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-11");
  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-15");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version =~ "^5\.0\.1") {
  if (version_is_less(version: version, test_version: "5.0.1.2234")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "5.0.1.2234", fixed_build: "20230322");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "5.0.1.2234") &&
     (!build || version_is_less(version: build, test_version: "20230322"))) {
    report = report_fixed_ver(installed_version: version, fixed_version: "5.0.1.2234", fixed_build: "20230322");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
