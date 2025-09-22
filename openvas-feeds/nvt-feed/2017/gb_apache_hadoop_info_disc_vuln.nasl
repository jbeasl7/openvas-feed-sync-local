# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:hadoop";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140342");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-08-31 16:46:30 +0700 (Thu, 31 Aug 2017)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-03 21:15:00 +0000 (Sat, 03 Jul 2021)");

  script_cve_id("CVE-2016-5001");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Hadoop Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_hadoop_detect.nasl");
  script_mandatory_keys("Apache/Hadoop/Installed");

  script_tag(name:"summary", value:"Apache Hadoop is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This is an information disclosure vulnerability in the short-circuit reads
feature of HDFS. A local user on an HDFS DataNode may be able to craft a block token that grants unauthorized
read access to random files by guessing certain fields in the token.");

  script_tag(name:"impact", value:"A local user may be able to gain unauthorized read access to files.");

  script_tag(name:"affected", value:"Apache Hadoop version 2.7.1, 2.6.3 and earlier.");

  script_tag(name:"solution", value:"Update to version 2.6.4, 2.7.2 or later.");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q4/698");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.6.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.6.4");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.7.0", test_version2: "2.7.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.7.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
