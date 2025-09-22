# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155257");
  script_version("2025-09-03T05:38:18+0000");
  script_tag(name:"last_modification", value:"2025-09-03 05:38:18 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-02 02:12:46 +0000 (Tue, 02 Sep 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-07 19:28:25 +0000 (Wed, 07 Aug 2024)");

  script_cve_id("CVE-2025-29882", "CVE-2025-30264", "CVE-2025-30265", "CVE-2025-30267",
                "CVE-2025-30268", "CVE-2025-30272", "CVE-2025-30274", "CVE-2025-30270",
                "CVE-2025-30271", "CVE-2025-33032", "CVE-2025-30273", "CVE-2023-42464",
                "CVE-2022-22995", "CVE-2022-45188", "CVE-2024-38439", "CVE-2024-38440",
                "CVE-2024-38441");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Multiple Vulnerabilities (QSA-25-21, QSA-25-23)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-29882: NULL pointer dereference resulting in a denial of service (DoS)

  - CVE-2025-30264: Command injection

  - CVE-2025-30265: Buffer overflow may allow to modify memory or crash processes

  - CVE-2025-30267, CVE-2025-30268, CVE-2025-30272, CVE-2025-30274: NULL pointer dereference
  resulting in a denial of service (DoS)

  - CVE-2025-30270, CVE-2025-30271, CVE-2025-33032: Path traversal

  - CVE-2025-30273: Out-of-bounds write may allow to modify or corrupt memory

  - CVE-2023-42464, CVE-2022-22995, CVE-2022-45188, CVE-2024-38439, CVE-2024-38440, CVE-2024-38441:
  Multiple vulnerabilities in Netatalk");

  script_tag(name:"affected", value:"QNAP QTS version 5.x prior to 5.2.5.3145 build 20250526.

  Note: Due to the EOL status of 5.0.x and 5.1.x branches it is assumed that all 5.x versions are
  affected and not only the 5.2.x one as mentioned by the vendor.");

  script_tag(name:"solution", value:"Update to version 5.2.5.3145 build 20250526 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-25-21");
  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-25-23");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version =~ "^5\.") {
  if (version_is_less(version: version, test_version: "5.2.5.3145")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "5.2.5.3145", fixed_build: "20250526");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "5.2.5.3145") &&
      (!build || version_is_less(version: build, test_version: "20250526"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "5.2.5.3145", fixed_build: "20250526");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
