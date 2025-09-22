# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mariadb:mariadb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808066");
  script_version("2025-09-09T05:38:49+0000");
  script_cve_id("CVE-2015-3152");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-04 19:47:00 +0000 (Thu, 04 Aug 2022)");
  script_tag(name:"creation_date", value:"2016-06-02 18:23:47 +0530 (Thu, 02 Jun 2016)");
  script_name("MariaDB Man-in-the-Middle Attack Vulnerability (Jun 2016) - Linux");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mariadb/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-7937");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/show_bug.cgi?id=924663");

  script_tag(name:"summary", value:"MariaDB is prone to a man-in-the-middle (MITM) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to use of improper --ssl
  option when establishing a secure connection.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  man-in-the-middle attackers to spoof servers via a cleartext-downgrade
  attack.");

  script_tag(name:"affected", value:"MariaDB version 5.5.43 and earlier
  on Linux.");

  script_tag(name:"solution", value:"Upgrade to version MariaDB 5.5.44 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:version, test_version:"5.5.44")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"5.5.44");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
