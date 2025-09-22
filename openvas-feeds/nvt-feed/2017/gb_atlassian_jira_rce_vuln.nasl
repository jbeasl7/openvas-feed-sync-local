# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:atlassian:jira";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106758");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-04-18 10:31:18 +0200 (Tue, 18 Apr 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-15 01:01:00 +0000 (Sat, 15 Apr 2017)");

  script_cve_id("CVE-2017-5983");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Atlassian JIRA XXE / Deserialization Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_atlassian_jira_http_detect.nasl");
  script_mandatory_keys("atlassian/jira/detected");

  script_tag(name:"summary", value:"The JIRA Workflow Designer Plugin in Atlassian JIRA Server before 6.3.0
improperly uses an XML parser and deserializer, which allows remote attackers to execute arbitrary code, read
arbitrary files, or cause a denial of service via a crafted serialized Java object.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An anonymous user can perform multiple attacks on a vulnerable JIRA
instance that could cause remote code execution, the disclosure of private files or execute a denial of service
attack against the JIRA server. This vulnerability is caused by the way an XML parser and deserializer was used
in JIRA.");

  script_tag(name:"affected", value:"Atlassian JIRA 4.2.4 until 6.2.7.");

  script_tag(name:"solution", value:"Update to version 6.3.0 or later. Please keep in mind that JIRA Server 6.4
reaches its Atlassian Support end of life date on March 17, 2017, so it's recommended to upgrade to a version of
JIRA Software (7.0 or later).");

  script_xref(name:"URL", value:"https://confluence.atlassian.com/jira/jira-security-advisory-2017-03-09-879243455.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "4.2.4", test_version2: "6.2.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.3.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
