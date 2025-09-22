# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:ambari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812875");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-05-08 12:47:50 +0530 (Tue, 08 May 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-13 15:09:00 +0000 (Wed, 13 Jun 2018)");

  script_cve_id("CVE-2018-8003");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Ambari 1.4.0 - 2.6.1 Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_ambari_http_detect.nasl");
  script_mandatory_keys("apache/ambari/detected");

  script_tag(name:"summary", value:"Apache Ambari is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to Apache Ambari unable to sanitize against
  a crafted HTTP request.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to craft an HTTP
  request which provides read-only access to any file on the filesystem of the host.");

  script_tag(name:"affected", value:"Apache Ambari versions 1.4.0 through 2.6.1.");

  script_tag(name:"solution", value:"Update to version 2.6.2 or later.

  Please see the references for more information.");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/AMBARI/Ambari+Vulnerabilities#AmbariVulnerabilities-CVE-2018-8003");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/AMBARI/Installation+Guide+for+Ambari+2.6.2");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "1.4.0", test_version2: "2.6.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version:" 2.6.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
