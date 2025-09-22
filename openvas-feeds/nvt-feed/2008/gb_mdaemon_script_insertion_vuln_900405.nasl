# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:altn:mdaemon";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900405");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2008-6967");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MDaemon Server < 10.0.2 WordClient Script Insertion Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_altn_mdaemon_consolidation.nasl");
  script_mandatory_keys("altn/mdaemon/detected");

  script_tag(name:"summary", value:"MDaemon is prone to a script insertion vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This vulnerability is due to an input validation error in
  'HTML tags' in emails which are not properly filtered before displaying. This can be exploited
  when the malicious email is viewed.");

  script_tag(name:"impact", value:"An attacker can execute malicious arbitrary code in the email
  body.");

  script_tag(name:"affected", value:"MDaemon Server prior to version 10.0.2.");

  script_tag(name:"solution", value:"Update to version 10.0.2 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32142");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32355");
  script_xref(name:"URL", value:"http://files.altn.com/MDaemon/Release/RelNotes_en.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "10.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
