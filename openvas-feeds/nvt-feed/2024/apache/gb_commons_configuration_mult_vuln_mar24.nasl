# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:commons_configuration";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114451");
  script_version("2024-03-22T05:05:34+0000");
  script_tag(name:"last_modification", value:"2024-03-22 05:05:34 +0000 (Fri, 22 Mar 2024)");
  script_tag(name:"creation_date", value:"2024-03-21 14:58:28 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2024-29131", "CVE-2024-29133");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Commons Configuration 2.0.x < 2.10.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apache_commons_consolidation.nasl");
  script_mandatory_keys("apache/commons/configuration/detected");

  script_tag(name:"summary", value:"The Apache Commons Configuration library is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-29131, CONFIGURATION-840: StackOverflowError adding property in
  AbstractListDelimiterHandler.flattenIterator()

  - CVE-2024-29133, CONFIGURATION-841: StackOverflowError calling
  ListDelimiterHandler.flatten(Object, int) with a cyclical object tree");

  script_tag(name:"affected", value:"Apache Commons Configuration version 2.0.x prior to 2.10.1.");

  script_tag(name:"solution", value:"Update to version 2.10.1 or later.");

  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/03/20/4");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/03/20/3");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/2dn0hpwhhyj2m7pjcww027h8ws9qk8d1");
  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/CONFIGURATION-840");
  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/CONFIGURATION-841");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "2.0", test_version_up: "2.10.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.10.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
