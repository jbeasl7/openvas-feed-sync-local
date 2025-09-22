# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mailenable:mailenable";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100798");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-09-14 15:16:41 +0200 (Tue, 14 Sep 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2010-2580");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MailEnable <= 4.25 Multiple DoS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("SMTP problems");
  script_dependencies("gb_mailenable_consolidation.nasl");
  script_mandatory_keys("mailenable/detected");

  script_tag(name:"summary", value:"MailEnable is prone to multiple remote denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to crash the affected
  application, denying service to legitimate users.");

  script_tag(name:"affected", value:"MailEnable 4.25 Standard Edition, Professional Edition, and
  Enterprise Edition are vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"The vendor has released hotfix ME-10044. Please see the
  references for more information.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43182");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2010-112/");
  script_xref(name:"URL", value:"http://www.mailenable.com/hotfix/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/513648");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "4.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.26");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
