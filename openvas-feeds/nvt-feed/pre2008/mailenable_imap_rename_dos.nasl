# SPDX-FileCopyrightText: 2006 Josh Zlatin-Amishav
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mailenable:mailenable";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20245");
  script_version("2023-05-11T09:09:33+0000");
  script_tag(name:"last_modification", value:"2023-05-11 09:09:33 +0000 (Thu, 11 May 2023)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2005-3813");
  script_xref(name:"OSVDB", value:"21109");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MailEnable <= 1.7 IMAP Rename DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2006 Josh Zlatin-Amishav");
  script_family("Denial of Service");
  script_dependencies("gb_mailenable_consolidation.nasl");
  script_mandatory_keys("mailenable/detected");

  script_tag(name:"summary", value:"MailEnable is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The IMAP server bundled with the version of MailEnable
  Professional or Enterprise Edition installed on the remote host is prone to crash due to
  incorrect handling of mailbox names in the rename command.");

  script_tag(name:"impact", value:"An authenticated remote attacker can exploit this flaw to crash
  the IMAP server on the remote host.");

  script_tag(name:"solution", value:"Apply the IMAP Cumulative Hotfix/Update provided in the
  referenced zip file.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/417589");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15556");
  script_xref(name:"URL", value:"http://www.mailenable.com/hotfix/MEIMAPS.ZIP");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "1.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See reference");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
