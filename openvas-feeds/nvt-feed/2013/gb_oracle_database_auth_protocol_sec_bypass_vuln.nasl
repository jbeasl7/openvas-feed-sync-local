# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:database_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803957");
  script_version("2025-09-05T15:40:40+0000");
  script_cve_id("CVE-2012-3137");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-10-28 17:27:36 +0530 (Mon, 28 Oct 2013)");
  script_name("Oracle Database Server Authentication Protocol Security Bypass Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass the authentication
  process, gain unauthorized access to the database and obtain sensitive information.");

  script_tag(name:"affected", value:"Oracle Database Server versions 10.2.0.3, 10.2.0.4, 10.2.0.5, 11.1.0.7,
  11.2.0.2, and 11.2.0.3");

  script_tag(name:"insight", value:"Flaw is due to an error occurs in the authentication protocol.

  A flaw exists in authentication protocol, which allows arbitrary users to obtain session key and salt.");

  script_tag(name:"solution", value:"Apply the updates from the referenced advisories.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"summary", value:"Oracle Database Server is prone to a security bypass vulnerability.");

  script_xref(name:"URL", value:"http://securitytracker.com/id?1027558");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55651");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/22069");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/117503");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("gb_oracle_database_consolidation.nasl");
  script_mandatory_keys("oracle/database/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

ver = infos["version"];
path = infos["location"];

if(ver =~ "^(11\.[1|2]\.0|10\.2\.0)") {
  if(version_in_range(version:ver, test_version:"10.2.0.3", test_version2:"10.2.0.5")||
     version_in_range(version:ver, test_version:"11.2.0.2", test_version2:"11.2.0.3")||
     version_is_equal(version:ver, test_version:"11.1.0.7")) {
    report = report_fixed_ver( installed_version:ver, fixed_version:"See references", install_path:path );
    security_message( port:port, data:report );
    exit(0);
  }
}
exit(99);
