# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:group-office:group-office_groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100802");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-09-14 15:16:41 +0200 (Tue, 14 Sep 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-3428");
  script_name("Group-Office 'modules/notes/json.php' SQL Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_groupoffice_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("groupoffice/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43174");

  script_tag(name:"summary", value:"Group-Office is prone to an SQL-injection vulnerability because it
  fails to sufficiently sanitize user-supplied data before using it in an SQL query.");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to execute arbitrary
  code, compromise the application, access or modify data, or exploit
  latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Group-Office 3.5.9 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less_equal(version:version, test_version:"3.5.9")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"None", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
