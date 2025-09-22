# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:limesurvey:limesurvey";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106064");
  script_version("2025-07-24T05:43:49+0000");
  script_tag(name:"last_modification", value:"2025-07-24 05:43:49 +0000 (Thu, 24 Jul 2025)");
  script_tag(name:"creation_date", value:"2016-05-13 09:53:01 +0700 (Fri, 13 May 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("LimeSurvey 2.05x < 2.06+ Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("secpod_limesurvey_detect.nasl");
  script_mandatory_keys("limesurvey/http/detected");

  script_tag(name:"summary", value:"LimeSurvey is prone to multiple vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Unauthenticated local file disclosure
  An attacker can craft a malicious PHP serialized string containing a list of arbitrary files. This
  list can be sent to the Lime Survey backup feature for downloading without prior authentication.
  Any files accessible with the privileges of the web server user can be downloaded.

  - Unauthenticated database dump
  An attacker can request the database backup feature without authentication. The whole Lime Survey
  database can be downloaded including username and hashed password of the administrator account.

  - Unauthenticated arbitrary remote code execution
  An attacker can inject arbitrary PHP code into the application source code allowing to plant a
  malicious web backdoor to access underlying web server.

  - Multiple reflective cross-site scripting
  The application is prone to multiple reflective cross-site scripting vulnerabilities.

  - CVE-2025-34120: An unauthenticated file download vulnerability exists as the application fails
  to validate serialized input to the admin backup endpoint (`index.php/admin/update/sa/backup`),
  allowing attackers to specify arbitrary file paths using a crafted `datasupdateinfo` payload. The
  files are packaged in a ZIP archive and made available for download without authentication. This
  vulnerability can be exploited to read arbitrary files on the host system, including sensitive OS
  and configuration files.");

  script_tag(name:"impact", value:"The impact ranges from unauthenticated file disclosure until
  remote code execution.");

  script_tag(name:"affected", value:"LimeSurvey version 2.05 to 2.06+ Build 151014");

  script_tag(name:"solution", value:"Update to LimeSurvey 2.06+ Build 151016 or later.");

  script_xref(name:"URL", value:"https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20151022-0_Lime_Survey_multiple_critical_vulnerabilities_v10.txt");
  script_xref(name:"URL", value:"https://sec-consult.com/vulnerability-lab/advisory/multiple-critical-vulnerabilities-in-lime-survey/");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if(version != "unknown") {
  if ((revcomp(a: version, b: "2.06+_build_151014") < 0) &&
      (revcomp(a: version, b: "2.05_build_150413") >= 0)) {
    report = report_fixed_ver(installed_version:version, fixed_version: "2.06+_build_151014");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
