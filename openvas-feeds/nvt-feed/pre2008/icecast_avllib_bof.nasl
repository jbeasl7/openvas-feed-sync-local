# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:icecast:icecast";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15401");
  script_version("2024-03-04T14:37:58+0000");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4415");
  script_cve_id("CVE-2002-0177");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("ICECast AVLlib remote buffer overflow");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");

  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Buffer overflow");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("icecast/banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to version 1.3.12 or later.");

  script_tag(name:"summary", value:"The remote server runs a version of ICECast, an open source streaming audio
server, which is older than version 1.3.12.

This version is affected by a remote buffer overflow because it does not properly check bounds of data send from
clients.

As a result of this vulnerability, it is possible for a remote attacker to cause a stack overflow and then execute
arbitrary code with the privilege of the server.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.3.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.12");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
