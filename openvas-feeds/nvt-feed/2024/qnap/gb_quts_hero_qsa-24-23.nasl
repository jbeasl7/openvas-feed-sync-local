# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:quts_hero";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126908");
  script_version("2024-09-12T07:59:53+0000");
  script_tag(name:"last_modification", value:"2024-09-12 07:59:53 +0000 (Thu, 12 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-05-28 08:20:42 +0000 (Tue, 28 May 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-11 13:39:09 +0000 (Wed, 11 Sep 2024)");

  script_cve_id("CVE-2024-21902", "CVE-2024-27127", "CVE-2024-27128", "CVE-2024-27129",
                "CVE-2024-27130", "CVE-2024-21904");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTS hero Multiple Vulnerabilities (QSA-24-23)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/quts_hero/detected");

  script_tag(name:"summary", value:"QNAP QuTS hero is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-21902: Incorrect permission assignment for critical resources vulnerability could allow
  remote attackers who have gained user access to read or modify critical resources.

  - CVE-2024-27127: Double free vulnerability could allow remote attackers who have gained user
  access to execute arbitrary code.

  - CVE-2024-27128, CVE-2024-27129, CVE-2024-27130: Buffer copy without checking size of input
  vulnerabilities could allow remote attackers who have gained user access to execute arbitrary
  code.

  - CVE-2024-21904: Path traversal vulnerability could allow remote users to read the contents of
  unexpected files and expose sensitive data.");

  script_tag(name:"affected", value:"QNAP QuTS hero version h5.1.x prior to h5.1.7.2770.");

  script_tag(name:"solution", value:"Update to version h5.1.7.2770 build 20240520 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-24-23");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/quts_hero/build");

if (version =~ "^h5\.1") {
  if (version_is_less(version: version, test_version: "h5.1.7.2770")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.1.7.2770", fixed_build: "20240520");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "h5.1.7.2770") &&
      (!build || version_is_less(version: build, test_version: "20240520"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.1.7.2770", fixed_build: "20240520");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
