# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808597");
  script_version("2025-09-09T05:38:49+0000");
  script_cve_id("CVE-2016-3518", "CVE-2016-3588", "CVE-2016-5436", "CVE-2016-5437", "CVE-2016-3424",
                "CVE-2016-5441", "CVE-2016-5442", "CVE-2016-5443");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-07-21 12:53:11 +0530 (Thu, 21 Jul 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Oracle MySQL Server 5.7 <= 5.7.12 Security Update (cpujul2016) - Linux");

  script_tag(name:"summary", value:"Oracle MySQL Server is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple unspecified errors exist in the 'MySQL Server' component
  via unknown vectors.");

  script_tag(name:"impact", value:"Successful exploitation will allow an authenticated remote attacker
  to affect integrity, and availability via unknown vectors.");

  script_tag(name:"affected", value:"Oracle MySQL Server versions 5.7 through 5.7.12.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujul2016.html#AppendixMSQL");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91967");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91983");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91906");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91917");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91976");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91915");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91974");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91963");
  script_xref(name:"Advisory-ID", value:"cpujul2016");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_unixoide");

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

if(version_in_range(version:vers, test_version:"5.7", test_version2:"5.7.12")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See the referenced vendor advisory", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
