# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:hadoop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813367");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2016-6811");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-10 13:12:00 +0000 (Thu, 10 May 2018)");
  script_tag(name:"creation_date", value:"2018-05-17 12:45:23 +0530 (Thu, 17 May 2018)");
  script_name("Apache Hadoop Privilege Escalation Vulnerability (May 2018)");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_hadoop_detect.nasl");
  script_mandatory_keys("Apache/Hadoop/Installed");

  script_tag(name:"summary", value:"Apache Hadoop is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a privilege escalation
  error while escalating to the yarn user.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker who can escalate to the yarn user to possibly run arbitrary commands
  as the root user.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"affected", value:"Apache Hadoop versions 2.2.0 to 2.7.3");

  script_tag(name:"solution", value:"Upgrade to Apache Hadoop version 2.7.4 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/9ba3c12bbdfd5b2cae60909e48f92608e00c8d99196390b8cfeca307@%3Cgeneral.hadoop.apache.org%3E");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if(version_in_range(version:version, test_version:"2.2.0", test_version2: "2.7.3")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"2.7.4", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
