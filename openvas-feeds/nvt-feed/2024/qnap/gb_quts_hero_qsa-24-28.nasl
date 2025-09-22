# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:quts_hero";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153044");
  script_version("2024-09-23T05:05:44+0000");
  script_tag(name:"last_modification", value:"2024-09-23 05:05:44 +0000 (Mon, 23 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-10 03:18:26 +0000 (Tue, 10 Sep 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-20 16:39:55 +0000 (Fri, 20 Sep 2024)");

  script_cve_id("CVE-2023-39298", "CVE-2024-32771");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTS hero Multiple Vulnerabilities (QSA-24-28)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/quts_hero/detected");

  script_tag(name:"summary", value:"QNAP QuTS hero is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-39298: A missing authorization could allow local attackers who have gained user access
  to access data or perform actions without the proper privileges

  - CVE-2024-32771: Improper restriction of excessive authentication attempts could allow attackers
  to use bruce force attacks to gain privileged access");

  script_tag(name:"affected", value:"QNAP QTS version 5.1.x.");

  script_tag(name:"solution", value:"Update to version h5.2.0.2782 build 20240601 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-24-28");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/quts_hero/build");

if (version =~ "^h5\.[12]") {
  if (version_is_less(version: version, test_version: "h5.2.0.2782")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.2.0.2782", fixed_build: "20240601");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "h5.2.0.2782") &&
      (!build || version_is_less(version: build, test_version: "20240520"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.2.0.2782", fixed_build: "20240601");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
