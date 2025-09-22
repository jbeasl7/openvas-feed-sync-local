# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:ambari";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106712");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-03-31 11:19:39 +0700 (Fri, 31 Mar 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-04 15:42:00 +0000 (Tue, 04 Apr 2017)");

  script_cve_id("CVE-2016-6807");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Ambari 2.4.0 - 2.4.1 Command Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_ambari_http_detect.nasl");
  script_mandatory_keys("apache/ambari/detected");

  script_tag(name:"summary", value:"Apache Ambrari is prone to an unauthenticated custom command
  execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Custom commands may be executed on the Ambari Agent hosts
  without authorization, leading to unauthorized access to operations that may affect the
  underlying system. Such operations are invoked by the Ambari Agent process on Ambari Agent hosts,
  as the user executing the Ambari Agent process.");

  script_tag(name:"affected", value:"Apache Ambari version 2.4.0 through 2.4.1.");

  script_tag(name:"solution", value:"Update to version 2.4.2 or later.");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/AMBARI/Ambari+Vulnerabilities#AmbariVulnerabilities-FixedinAmbari2.4.2");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "2.4.0", test_version2: "2.4.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
