# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ilias:ilias";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813199");
  script_version("2024-02-20T05:05:48+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-19 15:12:00 +0000 (Tue, 19 Jun 2018)");
  script_tag(name:"creation_date", value:"2018-05-21 13:56:09 +0530 (Mon, 21 May 2018)");

  script_cve_id("CVE-2018-10306", "CVE-2018-10307", "CVE-2018-10428");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ILIAS LMS Multiple Vulnerabilities-02 (May 2018)");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_ilias_http_detect.nasl");
  script_mandatory_keys("ilias/detected");

  script_tag(name:"summary", value:"ILIAS LMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - CVE-2018-10306: Insufficient validation of input passed via 'invalid date' to
  'Services/Form/classes/class.ilDateDurationInputGUI.php' script and
  'Services/Form/classes/class.ilDateTimeInputGUI.php' script.

  - CVE-2018-10307: Insufficient validation of input passed via text of a PDO exception to 'error.php'
  script.

  - CVE-2018-10428: Due to inconsistencies in parameter handling, ILIAS is vulnerable to various
  instances of reflected cross-site scripting (XSS).");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to conduct XSS attacks and have unspecified impact on affected
  system.");

  script_tag(name:"affected", value:"ILIAS LMS 5.2.x prior to 5.2.15 and 5.3.x prior to 5.3.4.");

  script_tag(name:"solution", value:"Update to version 5.2.15, 5.3.4 or later.");

  script_xref(name:"URL", value:"https://www.ilias.de/docu/ilias.php?ref_id=35&obj_id=116792&from_page=116805&cmd=layout&cmdClass=illmpresentationgui&cmdNode=wc&baseClass=ilLMPresentationGUI");
  script_xref(name:"URL", value:"https://www.ilias.de/docu/ilias.php?ref_id=35&from_page=116799&obj_id=116799&cmd=layout&cmdClass=illmpresentationgui&cmdNode=wc&baseClass=ilLMPresentationGUI");
  script_xref(name:"URL", value:"https://www.ilias.de");


  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version =~ "^5\.3" && version_is_less(version:version, test_version:"5.3.4")) {
  fix = "5.3.4";
}
else if (version =~ "^5\.2" && version_is_less(version:version, test_version:"5.2.15")) {
  fix = "5.2.15";
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
