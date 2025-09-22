# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:ambari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809085");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-11-04 16:26:03 +0530 (Fri, 04 Nov 2016)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2015-3270");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Ambari 1.7.0 - 2.1.0 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_apache_ambari_http_detect.nasl");
  script_mandatory_keys("apache/ambari/detected");

  script_tag(name:"summary", value:"Apache Ambari is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an access to the user resource endpoint is
  not protected such that an authenticated user can remotely escalate his/her permissions to
  administrative level.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote authenticated users
  to gain administrative privileges, possibly related to changing passwords.");

  script_tag(name:"affected", value:"Apache Ambari versions 1.7.0, 2.0.0, 2.0.1 and 2.1.0.");

  script_tag(name:"solution", value:"Update to version 2.0.2, 2.1.1 or later.");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/10/13/3");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/AMBARI/Ambari+Vulnerabilities");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "1.7.0", test_version2: "2.0.1")) {
  fix = "2.0.2";
}
else if (version_is_equal(version: version, test_version:"2.1.0")) {
  fix = "2.1.1";
}

if (fix) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
