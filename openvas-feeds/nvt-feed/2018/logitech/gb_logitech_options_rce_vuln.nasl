# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:logitech:options";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112467");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-12-18 14:34:11 +0100 (Tue, 18 Dec 2018)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Logitech Options < 7.10.3 Remote Command Execution Vulnerability - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_logitech_options_detect_win.nasl");
  script_mandatory_keys("logitech/options/win/detected");

  script_tag(name:"summary", value:"Logitech Options is prone to a remote command execution (RCE)
  vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Upon installation of Logitech Options a WebSocket server is
being opened that any website can connect to, without any origin checking at all.

The only way of 'authentication' is by providing a pid (process ID) of a process owned by the
current user.
However, since there is no limitation of guesses, an attacker might be able to bypass this
authentication in microseconds.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to send commands
and options, configure the 'crown' to send arbitrary keystrokes to directly affect and manipulate
the target system and have other unspecified impact on it.");

  script_tag(name:"affected", value:"Logitech Options through version 7.0.564.");
  script_tag(name:"solution", value:"Update to Logitech Options version 7.10.3 or later.");

  script_xref(name:"URL", value:"https://bugs.chromium.org/p/project-zero/issues/detail?id=1663");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"7.10.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.10.3", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
