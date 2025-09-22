# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100409");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2009-12-18 16:46:00 +0100 (Fri, 18 Dec 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2009-4142", "CVE-2009-4143");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.2.12 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Attackers can exploit the code execution vulnerability to
  execute arbitrary code within the context of the PHP process. This may allow them to bypass
  intended security restrictions or gain elevated privileges.

  An attacker may leverage the cross-site scripting vulnerability to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may let the
  attacker steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"PHP versions prior to 5.2.12.");

  script_tag(name:"solution", value:"Update to version 5.2.12 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37390");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37389");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php#5.2.12");
  script_xref(name:"URL", value:"http://www.php.net/releases/5_2_12.php");
  script_xref(name:"URL", value:"http://www.suspekt.org/downloads/POC2009-ShockingNewsInPHPExploitation.pdf");
  script_xref(name:"URL", value:"http://www.blackhat.com/presentations/bh-usa-09/ESSER/BHUSA09-Esser-PostExploitationPHP-PAPER.pdf");
  script_xref(name:"URL", value:"http://d.hatena.ne.jp/t_komura/20091004/1254665511");
  script_xref(name:"URL", value:"http://bugs.php.net/bug.php?id=49785");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "5.2.0", test_version2: "5.2.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
