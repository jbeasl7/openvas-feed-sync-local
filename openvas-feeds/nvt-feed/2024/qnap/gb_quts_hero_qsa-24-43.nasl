# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:quts_hero";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153517");
  script_version("2024-11-27T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-11-27 05:05:40 +0000 (Wed, 27 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-11-26 07:46:24 +0000 (Tue, 26 Nov 2024)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:N");

  script_cve_id("CVE-2024-37041", "CVE-2024-37042", "CVE-2024-37043", "CVE-2024-37044",
                "CVE-2024-37045", "CVE-2024-37046", "CVE-2024-37047", "CVE-2024-37048",
                "CVE-2024-37049", "CVE-2024-37050", "CVE-2024-50396", "CVE-2024-50397",
                "CVE-2024-50398", "CVE-2024-50399", "CVE-2024-50400");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTS hero Multiple Vulnerabilities (QSA-24-43)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/quts_hero/detected");

  script_tag(name:"summary", value:"QNAP QuTS hero is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-37041, CVE-2024-37044, CVE-2024-37047, CVE-2024-37049, CVE-2024-37050: If exploited,
  the buffer overflow vulnerabilities could allow remote attackers who have gained administrator
  access to modify memory or crash processes.

  - CVE-2024-37042, CVE-2024-37045, CVE-2024-37048: If exploited, the NULL pointer dereference
  vulnerabilities could allow remote attackers who have gained administrator access to launch a
  denial of service (DoS) attack.

  - CVE-2024-37043, CVE-2024-37046: If exploited, the path traversal vulnerabilities could allow
  remote attackers who have gained administrator access to read the contents of unexpected files or
  system data.

  - CVE-2024-50396, CVE-2024-50397, CVE-2024-50398, CVE-2024-50399, CVE-2024-50400, CVE-2024-50401:
  If exploited, the use of externally-controlled format string vulnerabilities could allow remote
  attackers to obtain secret data or modify memory.");

  script_tag(name:"affected", value:"QNAP QuTS hero version h5.2.x.");

  script_tag(name:"solution", value:"Update to version h5.2.1.2929 build 20241025 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-24-43");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/quts_hero/build");

if (version =~ "^h5\.2") {
  if (version_is_less(version: version, test_version: "h5.2.1.2929")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.2.1.2929", fixed_build: "20241025");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "h5.2.1.2929") &&
      (!build || version_is_less(version: build, test_version: "20241025"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.2.1.2929", fixed_build: "20241025");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
