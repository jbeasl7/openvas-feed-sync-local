# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813120");
  script_version("2026-02-05T05:56:23+0000");
  script_tag(name:"last_modification", value:"2026-02-05 05:56:23 +0000 (Thu, 05 Feb 2026)");
  script_tag(name:"creation_date", value:"2018-04-20 10:36:37 +0530 (Fri, 20 Apr 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-18 15:37:13 +0000 (Wed, 18 Apr 2018)");

  script_cve_id("CVE-2017-7629", "CVE-2017-7630", "CVE-2017-7631", "CVE-2017-7632");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Multiple Vulnerabilities (NAS-201803-23)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2017-7629: Password verification step bypass vulnerability

  - CVE-2017-7630: Information disclosure vulnerability

  - CVE-2017-7631, CVE-2017-7632: Multiple cross-site scripting (XSS) vulnerabilities");

  script_tag(name:"affected", value:"QNAP QTS versions prior to 4.2.6 build 20171208 and 4.3.x prior
  to 4.3.3 build 20170901.");

  script_tag(name:"solution", value:"Update to version 4.2.6 build 20171028, 4.3.3 build 20170901 or
  later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/nas-201803-23");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version_is_less(version: version, test_version: "4.2.6")) {
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20171028");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.2.6") &&
   (!build || version_is_less(version: build, test_version: "20171028"))) {
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20171028");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^4\.3") {
  if (version_is_less(version: version, test_version: "4.3.3")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3", fixed_build: "20170901");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.3.3") &&
     (!build || version_is_less(version: build, test_version: "20170901"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3", fixed_build: "20170901");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
