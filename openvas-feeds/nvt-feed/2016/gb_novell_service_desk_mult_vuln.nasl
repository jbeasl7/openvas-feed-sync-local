# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:novell:service_desk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807538");
  script_version("2024-03-04T14:37:58+0000");
  script_cve_id("CVE-2016-1593", "CVE-2016-1594", "CVE-2016-1595", "CVE-2016-1596");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 19:59:00 +0000 (Tue, 09 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-04-06 16:24:55 +0530 (Wed, 06 Apr 2016)");
  script_name("Novell Service Desk Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Novell Service Desk is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An insufficient validation of user supplied input in the 'import users'
    and 'file download' functionalities.

  - A vulnerability in the access control enforcement of the file download
    functionality.

  - Insufficient validation of user supplied input via fields
   'tf_aClientFirstName', 'tf_aClientLastName' in customer portal,
   'ta_selectedTopicContent' in Forums, 'tf_orgUnitName' in
    User -> Organizational Units and 'manufacturer name', 'address' and 'city' in
    Configuration -> Vendors, other fields also might be vulnerable.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated attackers to upload arbitrary files to the server and this could
  lead to remote code execution, to read arbitrary file attachments, to inject
  arbitrary javascript into the context of other users' browser sessions
  (including administrative users) and to obtain sensitive information.");

  script_tag(name:"affected", value:"Novell Service Desk versions 7.0.3 and 7.1");

  script_tag(name:"solution", value:"Update to Novell Service Desk version 7.2
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/136646");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/538043");
  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=7017428");
  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=7017429");
  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=7017431");
  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=7017430");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_novell_service_desk_remote_detect.nasl");
  script_mandatory_keys("Novell/Service/Desk/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_equal(version:version, test_version:"7.0.3") ||
   version_is_equal(version:version, test_version:"7.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"7.2");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
