# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.119062");
  script_version("2025-07-17T05:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-16 08:04:51 +0000 (Wed, 16 Jul 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_cve_id("CVE-2021-3156");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Heap-Based Buffer Overflow Vulnerability (QSA-21-02, Baron Samedit)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to a heap-based buffer overflow vulnerability
  in sudo dubbed 'Baron Samedit'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Sudo is allowing privilege escalation to root via 'sudoedit -s'
  and a command-line argument that ends with a single backslash character.");

  script_tag(name:"affected", value:"QNAP QTS versions prior to 4.5.2.1566 Build 20210202.");

  script_tag(name:"solution", value:"Update to version 4.5.2.1566 Build 20210202 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-21-02");
  script_xref(name:"URL", value:"https://www.qnap.com/en/how-to/faq/article/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit");
  script_xref(name:"URL", value:"https://www.sudo.ws/releases/stable/#1.9.5p2");
  script_xref(name:"URL", value:"https://www.sudo.ws/releases/legacy/#1.8.32");
  script_xref(name:"URL", value:"https://www.sudo.ws/security/advisories/unescape_overflow/");
  script_xref(name:"URL", value:"https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version_is_less(version: version, test_version:"4.5.2.1566")) {
  report = report_fixed_ver(installed_version: version, installed_build: build,
                            fixed_version: "4.5.2.1566", fixed_build: "20210202");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.5.2.1566") &&
    (!build || version_is_less(version: build, test_version: "20210202"))) {
  report = report_fixed_ver(installed_version: version, installed_build: build,
                            fixed_version: "4.5.2.1566", fixed_build: "20210202");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
