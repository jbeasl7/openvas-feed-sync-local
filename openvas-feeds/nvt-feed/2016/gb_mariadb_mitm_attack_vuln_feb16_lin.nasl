# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mariadb:mariadb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806679");
  script_version("2025-09-09T05:38:49+0000");
  script_cve_id("CVE-2016-2047");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");
  script_tag(name:"creation_date", value:"2016-02-02 12:33:06 +0530 (Tue, 02 Feb 2016)");
  script_name("MariaDB MITM Vulnerability (MDEV-9212) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mariadb/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://mariadb.atlassian.net/browse/MDEV-9212");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/01/26/3");

  script_tag(name:"summary", value:"MariaDB is prone to a man-in-the-middle (MITM) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error within 'ssl_verify_server_cert'
  function which does improper verification of the server hostname in the subject's Common Name (CN)
  or subjectAltName field of the X.509 certificate.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to conduct
  a MITM attack.");

  script_tag(name:"affected", value:"MariaDB before versions 5.5.47, 10.0.x before 10.0.23, and
  10.1.x before 10.1.10.");

  script_tag(name:"solution", value:"Update to version 5.5.47, 10.0.23, 10.1.10 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(vers =~ "^10\.1\." && version_is_less(version:vers, test_version:"10.1.10")) {
  VULN = TRUE;
  fix = "10.1.10";
}

if(vers =~ "^10\.0\." && version_is_less(version:vers, test_version:"10.0.23")) {
  VULN = TRUE;
  fix = "10.0.23";
}

if(vers =~ "^5\." && version_is_less(version:vers, test_version:"5.5.47")) {
  VULN = TRUE;
  fix = "5.5.47";
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
