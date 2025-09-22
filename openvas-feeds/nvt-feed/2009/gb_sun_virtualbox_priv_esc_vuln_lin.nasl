# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sun:virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901052");
  script_version("2025-09-19T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-11-20 06:52:52 +0100 (Fri, 20 Nov 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3692");
  script_name("Sun VirtualBox < 3.0.8 'VBoxNetAdpCtl' Privilege Escalation Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36929");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36604");
  script_xref(name:"URL", value:"http://www.virtualbox.org/wiki/Changelog");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2845");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-268188-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("secpod_sun_virtualbox_detect_lin.nasl");
  script_mandatory_keys("Sun/VirtualBox/Lin/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let attacker to execute arbitrary commands
  with root privileges via specially crafted arguments.");

  script_tag(name:"affected", value:"Sun VirtualBox versions 3.x prior to 3.0.8.");

  script_tag(name:"insight", value:"The flaw is due to the 'VBoxNetAdpCtl' configuration tool improperly
  sanitising arguments before passing them in calls to 'popen()'.");

  script_tag(name:"solution", value:"Update to version 3.0.8 or later.");

  script_tag(name:"summary", value:"Sun VirtualBox is prone to a privilege escalation vulnerability.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^3\." && version_is_less(version:vers, test_version:"3.0.8")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.0.8", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
