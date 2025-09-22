# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811440");
  script_version("2025-09-09T05:38:49+0000");
  script_cve_id("CVE-2017-3732");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-29 20:43:00 +0000 (Mon, 29 Aug 2022)");
  script_tag(name:"creation_date", value:"2017-07-19 11:08:37 +0530 (Wed, 19 Jul 2017)");
  script_name("Oracle Mysql Security Updates (jul2017-3236622) 06 - Windows");

  script_tag(name:"summary", value:"Oracle MySQL is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in
  Security: Encryption (OpenSSL).");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to get sensitive information.");

  script_tag(name:"affected", value:"Oracle MySQL version 5.6.35 and earlier,
  5.7.17 and earlier on Windows");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html#AppendixMSQL");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95814");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:version, test_version:"5.6.0", test_version2:"5.6.35") ||
   version_in_range(version:version, test_version:"5.7.0", test_version2:"5.7.17")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"Apply the patch");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
