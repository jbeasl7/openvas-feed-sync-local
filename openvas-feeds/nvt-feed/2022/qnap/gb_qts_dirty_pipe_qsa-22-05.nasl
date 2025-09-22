# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124041");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2022-03-22 13:59:03 +0000 (Tue, 22 Mar 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-10 19:07:00 +0000 (Thu, 10 Mar 2022)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-0847");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Privilege Escalation Vulnerability (QSA-22-05)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to a local privilege escalation vulnerability,
  also known as dirty pipe.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If exploited, this vulnerability allows an unprivileged user to
  gain administrator privileges and inject malicious code.");

  script_tag(name:"affected", value:"QNAP QTS version 5.x prior to 5.0.0.1986 build 20220324.");

  script_tag(name:"solution", value:"Update to version 5.0.0.1986 build 20220324.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-22-05");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/166229/Dirty-Pipe-Linux-Privilege-Escalation.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version =~ "^5") {
  if (version_is_less(version: version, test_version: "5.0.0.1986")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "5.0.0.1986", fixed_build: "20220324");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "5.0.0.1986") &&
     (!build || version_is_less(version: build, test_version: "20220324"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "5.0.0.1986", fixed_build: "20220324");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
