# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154146");
  script_version("2025-03-11T05:38:16+0000");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-03-10 02:25:51 +0000 (Mon, 10 Mar 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:M/C:P/I:P/A:P");

  script_cve_id("CVE-2024-38638");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Out-of-bounds Write Vulnerability (QSA-24-52)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to an out-of-bounds write vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An out-of-bounds write vulnerability has been reported to
  affect certain QNAP operating system versions.");

  script_tag(name:"impact", value:"If exploited, the vulnerability could allow remote attackers who
  have gained administrator access to modify or corrupt memory.");

  script_tag(name:"affected", value:"QNAP QTS version 5.1.x prior to 5.1.9.2954 build 20241120.");

  script_tag(name:"solution", value:"Update to version 5.1.9.2954 build 20241120 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-24-52");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version =~ "^5\.1") {
  if (version_is_less(version: version, test_version: "5.1.9.2954")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "5.1.9.2954", fixed_build: "20241120");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "5.1.9.2954") &&
      (!build || version_is_less(version: build, test_version: "20241120"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "5.1.9.2954", fixed_build: "20241120");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
