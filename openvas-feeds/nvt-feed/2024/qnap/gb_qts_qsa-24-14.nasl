# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126679");
  script_version("2024-08-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-08-13 05:05:46 +0000 (Tue, 13 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-04-29 11:20:42 +0000 (Mon, 29 Apr 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:C");

  script_cve_id("CVE-2023-51364", "CVE-2023-51365", "CVE-2024-32765");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Multiple Vulnerabilities (QSA-24-14)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-51364, CVE-2023-51365: Path traversal vulnerabilities which could allow remote
  attackers to read sensitive data

  - CVE-2024-32765: An unknown vulnerability which could allow attackers to gain access to the
  system and execute certain functions");

  script_tag(name:"affected", value:"QNAP QTS version 4.5.x prior to 4.5.4.2627 and 5.1.x prior to
  5.1.8.2823.");

  script_tag(name:"solution", value:"Update to version 4.5.4.2627 build 20231225, 5.1.8.2823 build
  20240712 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-24-14");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version =~ "^4\.5") {
  if (version_is_less(version: version, test_version:"4.5.4.2627")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "4.5.4.2627", fixed_build: "20231225");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.5.4.2627") &&
      (!build || version_is_less(version: build, test_version: "20231225"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "4.5.4.2627", fixed_build: "20231225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^5\.1") {
  if (version_is_less(version: version, test_version: "5.1.8.2823")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "5.1.8.2823", fixed_build: "20240712");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "5.1.8.2823") &&
      (!build || version_is_less(version: build, test_version: "20240712"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "5.1.8.2823", fixed_build: "20240712");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
