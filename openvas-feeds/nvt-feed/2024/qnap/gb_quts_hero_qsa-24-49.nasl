# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:quts_hero";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131344");
  script_version("2024-12-13T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-12-13 05:05:32 +0000 (Fri, 13 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-12-11 09:33:50 +0000 (Wed, 11 Dec 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2024-48859", "CVE-2024-48865", "CVE-2024-48866", "CVE-2024-48867",
                "CVE-2024-48868", "CVE-2024-50393", "CVE-2024-50402", "CVE-2024-50403");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTS hero Multiple Vulnerabilities (QSA-24-49)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/quts_hero/detected");

  script_tag(name:"summary", value:"QNAP QuTS hero is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-48859: The imporper authentication could allow remote attackers to compromise the
  security of the system.

  - CVE-2024-48865: The improper certificate validation could allow attackers with local network
  access to compromise the security of the system.

  - CVE-2024-48866: The improper handling of URL encoding (hex encoding) could allow remote
  attackers to cause the system to go into an unexpected state.

  - CVE-2024-48867, CVE-2024-48868: The improper neutralization of CRLF sequences (CRLF injection)
  could allow remote attackers to modify application data.

  - CVE-2024-50393: The command injection could allow remote attackers to execute arbitrary
  commands.

  - CVE-2024-50402, CVE-2024-50403: The use of externally-controlled format string could allow
  remote attackers who have gained administrator access to obtain secret data or modify memory.");

  script_tag(name:"affected", value:"QNAP QuTS hero version h5.1.x prior to h5.1.9.2954 and h5.2.x
  prior to h5.2.2.2952.");

  script_tag(name:"solution", value:"Update to version h5.1.9.2954 build 20241120, h5.2.2.2952
  build 20241116 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-24-49");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/quts_hero/build");

if (version =~ "^h5\.1") {
  if (version_is_less(version: version, test_version: "h5.1.9.2954")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.1.9.2954", fixed_build: "20241120");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "h5.1.9.2954") &&
     (!build || version_is_less(version: build, test_version: "20241120"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.1.9.2954", fixed_build: "20241120");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^h5\.2") {
  if (version_is_less(version: version, test_version: "h5.2.2.2952")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.2.2.2952", fixed_build: "20241116");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "h5.2.2.2952") &&
     (!build || version_is_less(version: build, test_version: "20241116"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.2.2.2952", fixed_build: "20241116");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
