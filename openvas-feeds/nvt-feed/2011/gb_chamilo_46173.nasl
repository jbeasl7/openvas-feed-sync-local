# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:chamilo:chamilo_lms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103071");
  script_version("2025-04-24T05:40:00+0000");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:00 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2011-02-08 13:20:01 +0100 (Tue, 08 Feb 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Chamilo LMS < 1.8.8 Multiple Remote File Disclosure Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_chamilo_http_detect.nasl");
  script_mandatory_keys("chamilo/detected");

  script_tag(name:"summary", value:"Chamilo LMS is prone to multiple file disclosure vulnerabilities
  because it fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can exploit these vulnerabilities to view local
  files in the context of the webserver process. This may aid in further attacks.");

  script_tag(name:"affected", value:"Chamilo LMS version 1.8.7.1 is known to be affected. Other
  versions may also be affected.");

  script_tag(name:"solution", value:"Update to version 1.8.8 or later.");

  script_xref(name:"URL", value:"https://github.com/chamilo/chamilo-lms/wiki/security-issues#issue-5---2011-01-31---high-risk---filesystem-traversal-flaw");
  script_xref(name:"URL", value:"https://github.com/chamilo/chamilo-lms/wiki/security-issues#issue-4---2011-01-28---high-risk---filesystem-traversal-flaw");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210127130814/http://www.securityfocus.com/bid/46173");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/16114");
  script_xref(name:"URL", value:"https://seclists.org/bugtraq/2011/Feb/38");

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

if (version_is_less(version: version, test_version: "1.8.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.8.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
