# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:jackrabbit";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807898");
  script_cve_id("CVE-2016-6801");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-10-06 16:01:40 +0530 (Thu, 06 Oct 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-10-04 17:36:00 +0000 (Tue, 04 Oct 2016)");
  script_name("Apache Jackrabbit CSRF Vulnerability (Sep 2016) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_jackrabbit_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/jackrabbit/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/JCR-4009");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2016/09/14/6");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210123170657/http://www.securityfocus.com/bid/92966");

  script_tag(name:"summary", value:"Apache Jackrabbit is prone to a cross-site request forgery
  (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to error in content-type check for POST requests
  which does not handle missing Content-Type header fields, nor variations in field values with
  respect to upper/lower case or optional parameters.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct
  CSRF attacks.");

  script_tag(name:"affected", value:"Apache Jackrabbit versions 2.4.x prior to 2.4.6, 2.6.x prior to
  2.6.6, 2.8.x prior to 2.8.3, 2.10.x prior to 2.10.4, 2.12.x prior to 2.12.4 and 2.13.x prior to
  2.13.3 on Linux.");

  script_tag(name:"solution", value:"Update to version 2.4.6, 2.6.6, 2.8.3, 2.10.4, 2.12.4, 2.13.3
  or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if(version =~ "^2\.4\." && version_is_less(version: version, test_version: "2.4.6")) {
  VULN = TRUE;
  fix = "2.4.6";
}

else if(version =~ "^2\.6\." && version_is_less(version: version, test_version: "2.6.6")) {
  VULN = TRUE;
  fix = "2.6.6";
}

else if(version =~ "^2\.8\." && version_is_less(version: version, test_version: "2.8.3")) {
  VULN = TRUE;
  fix = "2.8.3";
}

else if(version =~ "^2\.10\." && version_is_less(version: version, test_version: "2.10.4")) {
  VULN = TRUE;
  fix = "2.10.4";
}

else if(version =~ "^2\.12\." && version_is_less(version: version, test_version: "2.12.4")) {
  VULN = TRUE;
  fix = "2.12.4";
}

else if(version =~ "^2\.13\." && version_is_less(version: version, test_version: "2.13.3")) {
  VULN = TRUE;
  fix = "2.13.3";
}

if(VULN) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
