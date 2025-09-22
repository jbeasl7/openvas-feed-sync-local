# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:business_intelligence_publisher";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813583");
  script_version("2023-07-20T05:05:18+0000");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-07-18 14:53:36 +0530 (Wed, 18 Jul 2018)");

  script_cve_id("CVE-2018-2958", "CVE-2018-2925");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle BI Publisher Multiple Privilege Escalation Vulnerabilities (cpujul2018)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_oracle_bi_publisher_detect.nasl");
  script_mandatory_keys("oracle/bi_publisher/detected");

  script_tag(name:"summary", value:"Oracle BI Publisher is prone to multiple privilege escalation vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to unspecified errors in the 'Security'
  and 'Web Server' components.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to escalate privileges
  and gain unauthorized rights to access and modify data.");

  script_tag(name:"affected", value:"Oracle BI Publisher versions 11.1.1.7.0, 11.1.1.9.0, 12.2.1.2.0 and 12.2.1.3.0.");

  script_tag(name:"solution", value:"See the referenced advisory for a solution.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujul2018.html#AppendixFMW");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_equal(version: version, test_version: "11.1.1.7.0") ||
    version_is_equal(version: version, test_version: "11.1.1.9.0") ||
    version_is_equal(version: version, test_version: "12.2.1.2.0") ||
    version_is_equal(version: version, test_version: "12.2.1.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
