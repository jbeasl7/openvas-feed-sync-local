# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:hadoop";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142481");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-06-03 03:26:39 +0000 (Mon, 03 Jun 2019)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2018-11767");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Hadoop KMS ACL Regression Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_hadoop_detect.nasl");
  script_mandatory_keys("Apache/Hadoop/Installed");

  script_tag(name:"summary", value:"Apache Hadoop is prone to a KMS ACL regression vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host");

  script_tag(name:"insight", value:"After the security fix for CVE-2017-15713, KMS has an access control
  regression, blocking users or granting access to users incorrectly, if the system uses non-default groups
  mapping mechanisms such as LdapGroupsMapping, CompositeGroupsMapping, or NullGroupsMapping.");

  script_tag(name:"affected", value:"Apache Hadoop versions 2.9.0 to 2.9.1, 2.8.3 to 2.8.4, 2.7.5 to 2.7.6.");

  script_tag(name:"solution", value:"Update to version 2.7.7, 2.8.5, 2.9.2 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/5fb771f66946dd5c99a8a5713347c24873846f555d716f9ac17bccca@%3Cgeneral.hadoop.apache.org%3E");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_in_range(version: version, test_version: "2.7.5", test_version2: "2.7.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.7.7", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.8.3", test_version2: "2.8.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.8.5", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.9.0", test_version2: "2.9.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.9.2", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
