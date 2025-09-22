# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:ambari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808650");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2016-08-09 18:48:58 +0530 (Tue, 09 Aug 2016)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-18 21:46:00 +0000 (Wed, 18 May 2016)");

  script_cve_id("CVE-2016-0707", "CVE-2015-5210");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Ambari 1.7 - 2.1.1 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_ambari_http_detect.nasl");
  script_mandatory_keys("apache/ambari/detected");

  script_tag(name:"summary", value:"Apache Ambari is prone to information disclosure and open
  redirection vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Weak permissions used for the '/var/lib/ambari-agent/data' and '/var/lib/ambari-agent/keys'
  directories by the agent.

  - An insufficient validation of user supplied input via 'targetURI' parameter in redirect and
  forward requests.");

  script_tag(name:"impact", value:"Success exploitation will allow local users to obtain sensitive
  information by reading files in the directories and to redirect users to arbitrary web sites and
  conduct phishing attacks.");

  script_tag(name:"affected", value:"Apache Ambari version 1.7 through 2.1.1.");

  script_tag(name:"solution", value:"Update to version 2.1.2 or later.");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/AMBARI/Ambari+Vulnerabilities");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version:version, test_version: "1.7", test_version2: "2.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.1.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
