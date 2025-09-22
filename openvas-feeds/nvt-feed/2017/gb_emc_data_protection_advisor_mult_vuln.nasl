# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dell:emc_data_protection_advisor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106939");
  script_version("2024-05-31T05:05:30+0000");
  script_tag(name:"last_modification", value:"2024-05-31 05:05:30 +0000 (Fri, 31 May 2024)");
  script_tag(name:"creation_date", value:"2017-07-11 15:10:44 +0700 (Tue, 11 Jul 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-17 17:58:00 +0000 (Mon, 17 Jul 2017)");

  script_cve_id("CVE-2017-8002", "CVE-2017-8003");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("EMC Data Protection Advisor Multiple Vulnerabilities (Jul 2017)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dell_data_protection_advisor_http_detect.nasl");
  script_mandatory_keys("dell/dpa/detected");

  script_tag(name:"summary", value:"EMC Data Protection Advisor is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2017-8002: Multiple blind SQL injection (SQLi)

  - CVE-2017-8003: Path traversal");

  script_tag(name:"affected", value:"EMC Data Protection Advisor prior to version 6.4");

  script_tag(name:"solution", value:"Update to version 6.4 or later.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Jul/12");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "6.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
