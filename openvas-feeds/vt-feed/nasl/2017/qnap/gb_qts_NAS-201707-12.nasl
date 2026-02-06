# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106880");
  script_version("2026-02-05T05:56:23+0000");
  script_tag(name:"last_modification", value:"2026-02-05 05:56:23 +0000 (Thu, 05 Feb 2026)");
  script_tag(name:"creation_date", value:"2017-06-16 16:07:13 +0700 (Fri, 16 Jun 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-7876");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Command Injection Vulnerability (NAS-201707-12)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to a command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"This command injection vulnerability allows attackers to run
  arbitrary commands in the compromised application.");

  script_tag(name:"affected", value:"QNAP QTS versions prior to 4.2.6 build 20170517 and 4.3.x prior
  to 4.3.3.0174 build 20170503.");

  script_tag(name:"solution", value:"Update to version 4.2.6 build 20170517, 4.3.3.0174 build
  20170503 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/nas-201707-12");
  script_xref(name:"URL", value:"https://www.qnap.com/en/release-notes/qts/4.2.6/20170517");
  script_xref(name:"URL", value:"https://www.qnap.com/en/release-notes/qts/4.3.3.0174/20170503");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version_is_less(version: version, test_version: "4.2.6")) {
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20170517");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.2.6") &&
   (!build || version_is_less(version: build, test_version: "20170517"))) {
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20170517");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^4\.3") {
  if (version_is_less(version: version, test_version: "4.3.3.0174")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3.0174", fixed_build: "20170503");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "4.3.3.0174") &&
     (!build || version_is_less(version: build, test_version: "20170503"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3.0174", fixed_build: "20170503");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
