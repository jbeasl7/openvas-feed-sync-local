# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:ambari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113803");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2021-03-18 10:25:28 +0000 (Thu, 18 Mar 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-10 14:26:00 +0000 (Wed, 10 Mar 2021)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-1936");

  script_name("Apache Ambari < 2.7.4 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_ambari_http_detect.nasl");
  script_mandatory_keys("apache/ambari/detected");

  script_tag(name:"summary", value:"Apache Ambari is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to inject
  arbitrary HTML and JavaScript into the site.");

  script_tag(name:"affected", value:"Apache Ambari version 2.7.3 and prior.");

  script_tag(name:"solution", value:"Update to version 2.7.4 or later.");

  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/AMBARI-25329");
  script_xref(name:"URL", value:"https://mail-archives.apache.org/mod_mbox/ambari-user/202103.mbox/%3Cpony-f2a397f1aca7e00c4694311ba671caea2b10427b-ccfe61e3ef4d114a176a33ffc51f5b99d6e58d94%40user.ambari.apache.org%3E");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/03/02/1");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.7.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.7.4", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
