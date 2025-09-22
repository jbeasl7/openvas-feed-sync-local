# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154739");
  script_version("2025-06-13T15:42:54+0000");
  script_tag(name:"last_modification", value:"2025-06-13 15:42:54 +0000 (Fri, 13 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-06-13 07:39:33 +0000 (Fri, 13 Jun 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-18 19:15:29 +0000 (Tue, 18 Feb 2025)");

  script_cve_id("CVE-2025-26465", "CVE-2025-26466");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Multiple OpenSSH Vulnerabilities (QSA-25-14)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple vulnerabilities in OpenSSH.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"QNAP QTS version 5.x prior to 5.2.4.3079 build 20250321.

  Note: Due to the EOL status of 5.0.x and 5.1.x branches it is assumed that all 5.x versions are
  affected and not only the 5.2.x one as mentioned by the vendor.");

  script_tag(name:"solution", value:"Update to version 5.2.4.3079 build 20250321 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-25-14");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version =~ "^5\.") {
  if (version_is_less(version: version, test_version: "5.2.4.3079")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "5.2.4.3079", fixed_build: "20250321");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "5.2.4.3079") &&
      (!build || version_is_less(version: build, test_version: "20250321"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "5.2.4.3079", fixed_build: "20250321");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
