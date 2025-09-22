# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:splunk:splunk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901152");
  script_version("2024-02-26T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-02-26 05:06:11 +0000 (Mon, 26 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-21 21:08:34 +0000 (Wed, 21 Feb 2024)");

  script_cve_id("CVE-2010-3322", "CVE-2010-3323");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Splunk 4.0.0 - 4.1.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_splunk_http_detect.nasl");
  script_mandatory_keys("splunk/detected");

  script_tag(name:"summary", value:"Splunk is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - XML parser is vulnerable to XXE (XML eXternal Entity) attacks, which allows remote
  authenticated users to obtain sensitive information and gain privileges.

  - SPLUNKD_SESSION_KEY parameter is vulnerable to session hijacking.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain sensitive
  information and gain privileges.");

  script_tag(name:"affected", value:"Splunk version 4.0.0 through 4.1.4.");

  script_tag(name:"solution", value:"Update to version 4.1.5 or later.");

  script_xref(name:"URL", value:"http://www.splunk.com/view/SP-CAAAFQ6");

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

if (version_in_range(version: version, test_version: "4.0", test_version2:"4.1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.5", install_path:location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
