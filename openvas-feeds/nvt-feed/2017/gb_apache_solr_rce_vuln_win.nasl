# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:solr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108885");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-10-25 15:03:04 +0200 (Wed, 25 Oct 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-18 16:15:00 +0000 (Fri, 18 Jun 2021)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-12629");

  script_name("Apache Solr XEE and RCE Vulnerability (SOLR-11477) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_solr_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/solr/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Solr is vulnerable to an XML Entity Expansion (XEE)
  vulnerability leading to remote code execution (RCE).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the host.");

  script_tag(name:"insight", value:"Through XML Entity Expansion code from another, malicious host
  can be made to load and execute on the target host.");

  script_tag(name:"impact", value:"Successful exploitation would allow the attacker to execute
  arbitrary code on the host.");

  script_tag(name:"affected", value:"Apache Solr versions 5.1.0 to 5.5.4, 6.x prior to 6.6.2 and 7.x prior to 7.1.0.");

  script_tag(name:"solution", value:"Update to Apache Solr 5.5.5, 6.6.2, 7.1.0 or later.");

  script_xref(name:"URL", value:"http://lucene.472066.n3.nabble.com/Re-Several-critical-vulnerabilities-discovered-in-Apache-Solr-XXE-amp-RCE-td4358308.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101261");
  script_xref(name:"URL", value:"https://marc.info/?l=apache-announce&m=150786685013286");
  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/SOLR-11477");
  script_xref(name:"URL", value:"https://lucene.apache.org/solr/5_5_5/changes/Changes.html#v5.5.5.bug_fixes");
  script_xref(name:"URL", value:"https://lucene.apache.org/solr/6_6_2/changes/Changes.html#v6.6.2.bug_fixes");
  script_xref(name:"URL", value:"https://lucene.apache.org/solr/7_1_0/changes/Changes.html#v7.1.0.bug_fixes");

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

if (version_in_range(version: version, test_version: "5.1.0", test_version2: "5.5.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

else if (version_in_range(version: version, test_version: "6.0.0", test_version2: "6.6.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.6.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

else if (version_in_range(version: version, test_version: "7.0.0", test_version2: "7.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
