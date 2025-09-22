# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:bugzilla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801368");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-07-16 18:57:03 +0200 (Fri, 16 Jul 2010)");
  script_cve_id("CVE-2010-2470");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Bugzilla 'Install/Filesystem.pm' Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://www.bugzilla.org/status/changes.html");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=561797");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("bugzilla_detect.nasl");
  script_mandatory_keys("bugzilla/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to read sensitive configuration
  fields.");

  script_tag(name:"affected", value:"Bugzilla version 3.5.1 to 3.6.1 and 3.7 through 3.7.1.");

  script_tag(name:"insight", value:"The flaw is due to an error in 'install/Filesystem.pm', which uses
  world-readable permissions within 'bzr/' and 'data/webdot/'.");

  script_tag(name:"solution", value:"Upgrade Bugzilla 3.7.2 or later.");

  script_tag(name:"summary", value:"Bugzilla is prone to an information disclosure vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version:vers, test_version:"3.7", test_version2:"3.7.1") ||
    version_in_range(version:vers, test_version:"3.5.1", test_version2:"3.6.1")){
  security_message(port:port);
  exit(0);
}

exit(0);
