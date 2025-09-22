# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:altn:mdaemon";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14827");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2001-0584");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MDaemon IMAP Server DoS Vulnerability (CVE-2001-0584)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("gb_altn_mdaemon_consolidation.nasl");
  script_mandatory_keys("altn/mdaemon/detected");

  script_tag(name:"summary", value:"It is possible to crash the remote MDaemon IMAP server by
  sending a too long argument to the 'SELECT' or 'EXAMINE' commands.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"This problem allows an attacker to make the remote MDaemon
  server to crash, thus preventing legitimate users from receiving e-mails.");

  script_tag(name:"solution", value:"Update to the latest version.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2508");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version =~ "^[0-5]\.|6\.[0-7]") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
