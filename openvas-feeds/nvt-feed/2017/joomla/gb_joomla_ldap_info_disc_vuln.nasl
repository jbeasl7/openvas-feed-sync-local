# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112049");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-14596");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-27 17:43:00 +0000 (Wed, 27 Sep 2017)");
  script_tag(name:"creation_date", value:"2017-09-21 08:36:22 +0200 (Thu, 21 Sep 2017)");
  script_name("Joomla! < 3.8.0 LDAP Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"Joomla is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Joomla is prone to the following information disclosure vulnerability:

  - Inadequate escaping in the LDAP authentication plugin can result into a disclosure of username and password.");

  script_tag(name:"impact", value:"Successfully exploiting these issues will allow
  remote attackers to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"Joomla! versions 1.5.0 through 3.7.5");

  script_tag(name:"solution", value:"Upgrade to Joomla version 3.8.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/711-20170902-core-ldap-information-disclosure");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ver = get_app_version(cpe:CPE, port:port)){
  exit(0);
}

if(version_in_range(version:ver, test_version:"1.5.0", test_version2:"3.7.5"))
{
  report = report_fixed_ver(installed_version:ver, fixed_version:"3.8.0");
  security_message(data:report, port:port);
  exit(0);
}
exit(99);
