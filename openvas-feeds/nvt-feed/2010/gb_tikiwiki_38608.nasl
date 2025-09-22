# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tiki:tikiwiki_cms%2fgroupware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100537");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-03-15 19:33:39 +0100 (Mon, 15 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2010-1133", "CVE-2010-1134", "CVE-2010-1135", "CVE-2010-1136");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tiki Wiki CMS Groupware < 3.5, 4.x < 4.2 Multiple Unspecified Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_tikiwiki_http_detect.nasl");
  script_mandatory_keys("tiki/wiki/detected");

  script_tag(name:"summary", value:"Tiki Wiki CMS Groupware is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - An unspecified SQL-injection vulnerability

  - An unspecified authentication-bypass vulnerability

  - An unspecified vulnerability");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to compromise
  the application, access or modify data, exploit latent vulnerabilities in the underlying database,
  and gain unauthorized access to the affected application. Other attacks are also possible.");

  script_tag(name:"affected", value:"Tiki Wiki CMS Groupware prior to version 3.5 and 4.x prior to
  4.2.");

  script_tag(name:"solution", value:"Update to version 3.5, 4.2 or later.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20160715183707/http://www.securityfocus.com/bid/38608");
  script_xref(name:"URL", value:"http://tikiwiki.svn.sourceforge.net/viewvc/tikiwiki?view=rev&revision=24734");
  script_xref(name:"URL", value:"http://tikiwiki.svn.sourceforge.net/viewvc/tikiwiki?view=rev&revision=25046");
  script_xref(name:"URL", value:"http://tikiwiki.svn.sourceforge.net/viewvc/tikiwiki?view=rev&revision=25424");
  script_xref(name:"URL", value:"http://tikiwiki.svn.sourceforge.net/viewvc/tikiwiki?view=rev&revision=25435");
  script_xref(name:"URL", value:"http://info.tikiwiki.org/article86-Tiki-Announces-3-5-and-4-2-Releases");
  script_xref(name:"URL", value:"http://info.tikiwiki.org/tiki-index.php?page=homepage");

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

if (version_is_less(version: version, test_version: "3.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "4.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
