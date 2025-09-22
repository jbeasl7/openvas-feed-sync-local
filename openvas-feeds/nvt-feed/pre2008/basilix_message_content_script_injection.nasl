# SPDX-FileCopyrightText: 2004 George A. Theall
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:basilix:basilix_webmail";

if (description) {
  script_oid("1.3.6.1.4.1.25623.1.0.14218");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2002-1708");

  script_name("BasiliX Message Content Script Injection Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");

  script_copyright("Copyright (C) 2004 George A. Theall");

  script_dependencies("basilix_detect.nasl");
  script_mandatory_keys("basilix/installed");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to BasiliX version 1.1.1 or later.");

  script_tag(name:"summary", value:"The remote web server contains PHP scripts that are prone to cross-site
scripting attacks.

Description :

The remote host appears to be running a BasiliX version 1.1.0 or lower. Such versions are vulnerable to
cross-scripting attacks since they do not filter HTML tags when showing a message.  As a result, an attacker can
include arbitrary HTML and script code in a message and have that code executed by the user's browser when it is
viewed.");

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/vulnwatch/2002-q2/0117.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5060");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
