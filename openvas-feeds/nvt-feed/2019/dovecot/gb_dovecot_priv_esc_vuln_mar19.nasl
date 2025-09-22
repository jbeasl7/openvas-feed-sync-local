# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113378");
  script_version("2024-11-22T15:40:47+0000");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2019-04-29 11:00:46 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-14 03:29:00 +0000 (Fri, 14 Jun 2019)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-7524");

  script_name("Dovecot < 2.2.36.3, 2.3.x < 2.3.5.1 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_dovecot_consolidation.nasl");
  script_mandatory_keys("dovecot/detected");

  script_tag(name:"summary", value:"Dovecot is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A local attacker can cause a buffer overflow in the indexer-worker process.
  This occurs because of missing checks in the fts and pop3-uidl components.");

  script_tag(name:"impact", value:"Successful exploitation would allow a local attacker to elevate to root.");

  script_tag(name:"affected", value:"Dovecot version 2.0.14 through 2.2.36.2 and version 2.3.0 through version 2.3.5.0.");

  script_tag(name:"solution", value:"Update to version 2.2.36.3 or 2.3.5.1 respectively.");

  script_xref(name:"URL", value:"https://dovecot.org/list/dovecot-news/2019-March/000403.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/107672");

  exit(0);
}

CPE = "cpe:/a:dovecot:dovecot";

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "2.0.14", test_version2: "2.2.36.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.36.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

else if (version_in_range(version: version, test_version: "2.3.0", test_version2: "2.3.5.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.5.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
