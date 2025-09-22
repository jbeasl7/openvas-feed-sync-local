# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:filezilla:filezilla_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900519");
  script_version("2024-07-24T05:06:37+0000");
  script_tag(name:"last_modification", value:"2024-07-24 05:06:37 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"creation_date", value:"2009-03-23 08:26:42 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-0884");
  script_name("FileZilla Server < 0.9.31 Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_filezilla_server_ftp_detect.nasl");
  script_mandatory_keys("filezilla/server/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/34089");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34006");
  script_xref(name:"URL", value:"http://sourceforge.net/project/shownotes.php?release_id=665428");

  script_tag(name:"summary", value:"FileZilla Server is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is generated due to an error in unspecified vectors
  while handling SSL/TLS packets.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker crash the
  application to cause denial of service.");

  script_tag(name:"affected", value:"FileZilla Server versions prior to 0.9.31.");

  script_tag(name:"solution", value:"Update to version 0.9.31 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"0.9.31")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"0.9.31", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
