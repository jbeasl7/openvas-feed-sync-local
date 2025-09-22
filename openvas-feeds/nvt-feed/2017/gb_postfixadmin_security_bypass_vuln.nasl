# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postfix_admin_project:postfix_admin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106680");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-03-21 14:09:13 +0700 (Tue, 21 Mar 2017)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-26 16:59:00 +0000 (Wed, 26 Feb 2020)");

  script_cve_id("CVE-2017-5930");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Postfix Admin Security Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_postfixadmin_detect.nasl");
  script_mandatory_keys("postfixadmin/installed");

  script_tag(name:"summary", value:"Postfix Admin is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The AliasHandler component allows remote authenticated domain admins to
delete protected aliases via the delete parameter to delete.php, involving a missing permission check.");

  script_tag(name:"affected", value:"Postfix Admin before version 3.0.2.");

  script_tag(name:"solution", value:"Update to version 3.0.2 or later.");

  script_xref(name:"URL", value:"https://sourceforge.net/p/postfixadmin/mailman/message/35646827/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96142");
  script_xref(name:"URL", value:"https://github.com/postfixadmin/postfixadmin/pull/23");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
