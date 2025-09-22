# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147646");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-02-17 03:34:21 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-10 14:59:00 +0000 (Thu, 10 Mar 2022)");

  script_cve_id("CVE-2016-2124", "CVE-2020-25717", "CVE-2020-25718", "CVE-2020-25719",
                "CVE-2020-25722", "CVE-2021-3738", "CVE-2020-25721", "CVE-2021-23192");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS 5.x < 5.0.0.1891 build 20211221 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"QNAP QTS version 5.x.");

  script_tag(name:"solution", value:"Update to version 5.0.0.1891 build 20211221 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/release-notes/qts/5.0.0.1891/20211221");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version =~ "^5") {
  if (version_is_less(version: version, test_version: "5.0.0.1891")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "5.0.0.1891", fixed_build: "20211221");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "5.0.0.1891") &&
     (!build || version_is_less(version: build, test_version: "20211221"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "5.0.0.1891", fixed_build: "20211221");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
