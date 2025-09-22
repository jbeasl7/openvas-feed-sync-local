# SPDX-FileCopyrightText: 2004 George A. Theall
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:basilix:basilix_webmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14304");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("BasiliX Arbitrary Command Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2004 George A. Theall");
  script_dependencies("basilix_detect.nasl");
  script_mandatory_keys("basilix/installed");

  script_tag(name:"solution", value:"Upgrade to BasiliX version 1.1.0 or later.");

  script_tag(name:"summary", value:"The remote web server contains a BasiliX PHP script that
  is prone to arbitrary.");

  script_tag(name:"insight", value:"The remote host appears to be running a version of BasiliX
  between 1.0.2beta or 1.0.3beta. In such versions, the script 'login.php3' fails to sanitize user
  input, which enables a remote attacker to pass in a specially crafted value for the parameter
  'username' with arbitrary commands to be executed on the target using the permissions of the web server.");

  script_xref(name:"URL", value:"http://www.derkeiler.com/Mailing-Lists/securityfocus/bugtraq/2001-09/0017.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3276");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);