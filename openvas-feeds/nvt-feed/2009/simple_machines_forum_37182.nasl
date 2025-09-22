# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:simplemachines:smf";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100371");
  script_version("2025-07-25T05:44:05+0000");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"creation_date", value:"2009-12-02 17:30:58 +0100 (Wed, 02 Dec 2009)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-10 18:53:34 +0000 (Mon, 10 Feb 2020)");

  script_cve_id("CVE-2009-5068", "CVE-2013-0192");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Simple Machines Forum (SMF) < 1.1.11, 2.0 RC2 Multiple Security Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_simple_machines_forum_http_detect.nasl");
  script_mandatory_keys("smf/detected");

  script_tag(name:"summary", value:"Simple Machines Forum (SMF) is prone to multiple security
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - A remote PHP code-execution vulnerability

  - Multiple cross-site scripting vulnerabilities

  - Multiple cross-site request-forgery vulnerabilities

  - An information disclosure vulnerability

  - Multiple denial-of-service vulnerabilities");

  script_tag(name:"impact", value:"Attackers can exploit these issues to execute arbitrary script
  code within the context of the webserver, perform unauthorized actions on behalf of legitimate
  users, compromise the affected application, steal cookie-based authentication credentials, obtain
  information that could aid in further attacks or cause denial-of-service conditions.");

  script_tag(name:"affected", value:"SMF version 2.0 RC2 is known to be affected. Some of these
  issues also affect version 1.1.10 and earlier.");

  script_tag(name:"solution", value:"Reportedly, the vendor fixed some of the issues in the release
  1.1.11.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210123104913/http://www.securityfocus.com/bid/37182");
  script_xref(name:"URL", value:"https://web.archive.org/web/20160528041358/http://code.google.com/p/smf2-review/issues/list");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2013/01/17/5");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2013/01/31/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2013/02/01/4");

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

if (version_is_less_equal(version: version, test_version: "1.1.10") ||
    version_is_equal(version: version, test_version: "2.0rc2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
