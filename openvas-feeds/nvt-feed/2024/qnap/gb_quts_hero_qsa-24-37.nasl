# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:quts_hero";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153516");
  script_version("2024-11-27T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-11-27 05:05:40 +0000 (Wed, 27 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-11-26 07:31:53 +0000 (Tue, 26 Nov 2024)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-31 17:07:07 +0000 (Mon, 31 Jul 2023)");

  script_cve_id("CVE-2020-14145", "CVE-2021-41617", "CVE-2023-38408");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTS hero Multiple OpenSSH Vulnerabilities (QSA-24-37)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/quts_hero/detected");

  script_tag(name:"summary", value:"QNAP QuTS hero is prone to multiple vulnerabilities in
  OpenSSH.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been reported in OpenSSH. The
  vulnerabilities have been found to affect certain QNAP operating system versions.");

  script_tag(name:"affected", value:"QNAP QuTS hero version h5.1.x.");

  script_tag(name:"solution", value:"Update to version h5.1.8.2823 build 20240712 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-24-37");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/quts_hero/build");

if (version =~ "^h5\.1") {
  if (version_is_less(version: version, test_version: "h5.1.8.2823")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.1.8.2823", fixed_build: "20240712");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "h5.1.8.2823") &&
      (!build || version_is_less(version: build, test_version: "20240712"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.1.8.2823", fixed_build: "20240712");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
