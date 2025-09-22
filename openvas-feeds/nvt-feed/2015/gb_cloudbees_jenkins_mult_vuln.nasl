# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807001");
  script_version("2024-12-03T05:05:44+0000");
  script_cve_id("CVE-2015-5317", "CVE-2015-5318", "CVE-2015-5319", "CVE-2015-5320",
                "CVE-2015-5321", "CVE-2015-5322", "CVE-2015-5323", "CVE-2015-5324",
                "CVE-2015-5325", "CVE-2015-5326", "CVE-2015-8103", "CVE-2015-7536",
                "CVE-2015-7537", "CVE-2015-7538", "CVE-2015-7539");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-12-03 05:05:44 +0000 (Tue, 03 Dec 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-09 02:16:00 +0000 (Tue, 09 Jan 2024)");
  script_tag(name:"creation_date", value:"2015-12-15 17:52:00 +0530 (Tue, 15 Dec 2015)");

  script_name("Jenkins Multiple Vulnerabilities (Nov 2015) - Windows");

  script_tag(name:"summary", value:"Jenkins is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error in 'Fingerprints' pages.

  - The usage of publicly accessible salt to generate CSRF protection tokens.

  - The XML external entity (XXE) vulnerability in the create-job CLI command.

  - An improper verification of the shared secret used in JNLP slave
    connections.

  - An error in sidepanel widgets in the CLI command overview and help
    pages.

  - The directory traversal vulnerability in while requesting jnlpJars.

  - An improper restriction on access to API tokens.

  - The cross-site scripting vulnerability in the slave overview page.

  - The unsafe deserialization in Jenkins remoting.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information, bypass the protection mechanism,
  gain elevated privileges, bypass intended access restrictions and execute
  arbitrary code.");

  script_tag(name:"affected", value:"All Jenkins main line releases up to and including 1.637,
  all Jenkins LTS releases up to and including 1.625.1.");

  script_tag(name:"solution", value:"Jenkins main line users should update to 1.638,
  Jenkins LTS users should update to 1.625.2.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.jenkins.io/security/advisory/2015-11-11/");
  script_xref(name:"URL", value:"https://www.jenkins.io/blog/2015/11/06/mitigating-unauthenticated-remote-code-execution-0-day-in-jenkins-cli/");
  script_xref(name:"URL", value:"https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/");
  script_xref(name:"URL", value:"https://github.com/foxglovesec/JavaUnserializeExploits/blob/master/jenkins.py");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2015/q4/241");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210122210513/http://www.securityfocus.com/bid/77572");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210122210513/http://www.securityfocus.com/bid/77570");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210122210513/http://www.securityfocus.com/bid/77574");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210122210513/http://www.securityfocus.com/bid/77636");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210122210513/http://www.securityfocus.com/bid/77619");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_windows");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_full(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
proto = infos["proto"];

if(get_kb_item("jenkins/" + port + "/is_lts")) {
  if(version_is_less(version:version, test_version:"1.625.2")) {
    vuln = TRUE;
    fix = "1.625.2";
  }
} else {
  if(version_is_less(version:version, test_version:"1.638")) {
    vuln = TRUE;
    fix = "1.638";
  }
}

if(vuln) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(port:port, data:report, proto:proto);
  exit(0);
}

exit(99);
