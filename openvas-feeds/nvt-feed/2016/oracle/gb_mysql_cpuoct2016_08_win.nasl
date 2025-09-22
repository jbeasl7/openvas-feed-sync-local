# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809384");
  script_version("2025-09-09T05:38:49+0000");
  script_cve_id("CVE-2016-8287", "CVE-2016-3495", "CVE-2016-5628", "CVE-2016-8290", "CVE-2016-5633",
                "CVE-2016-5631", "CVE-2016-8289", "CVE-2016-5634", "CVE-2016-5635");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-26 16:38:00 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"creation_date", value:"2016-10-19 15:53:16 +0530 (Wed, 19 Oct 2016)");
  script_name("Oracle MySQL Server 5.7 <= 5.7.13 Security Update (cpuoct2016) - Windows");

  script_tag(name:"summary", value:"Oracle MySQL Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple unspecified errors within
  the 'Server: DML', 'Server: InnoDB', 'Server: Memcached', 'Server: Performance Schema', 'Server: RBR',
  'Server: Security: Audit' and 'Server: Replication' components.");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities will allow remote
  a remote user to cause denial of service conditions.");

  script_tag(name:"affected", value:"Oracle MySQL Server versions 5.7 through 5.7.13.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuoct2016.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpuoct2016");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:oracle:mysql";

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"5.7", test_version2:"5.7.13")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See the referenced vendor advisory", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
