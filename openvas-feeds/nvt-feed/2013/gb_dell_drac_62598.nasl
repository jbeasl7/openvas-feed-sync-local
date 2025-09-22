# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103808");
  script_version("2024-07-12T05:05:45+0000");
  script_tag(name:"last_modification", value:"2024-07-12 05:05:45 +0000 (Fri, 12 Jul 2024)");
  script_tag(name:"creation_date", value:"2013-10-14 11:13:22 +0200 (Mon, 14 Oct 2013)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2013-3589");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dell iDRAC6 and iDRAC7 'ErrorMsg' Parameter XSS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_dell_drac_idrac_consolidation.nasl");
  script_mandatory_keys("dell/idrac/detected");

  script_tag(name:"summary", value:"Dell iDRAC6 and iDRAC7 devices are prone to a cross-site
  scripting (XSS) vulnerability because they fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks the firmware version.");

  script_tag(name:"insight", value:"Dell iDRAC 6 and Dell iDRAC 7 administrative web interface login
  page can allow remote attackers to inject arbitrary script via the vulnerable query string
  parameter ErrorMsg.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may let the
  attacker steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Dell iDRAC6 1.95 and previous versions, Dell iDRAC7 1.40.40 and
  previous versions.

  NOTE: iDRAC6 'modular' (blades) are not affected, no updates are required.");

  script_tag(name:"solution", value:"Firmware updates will be posted to the Dell support page when
  available. Users should download the appropriate update for the version of iDRAC they have
  installed:

  - iDRAC6 'monolithic' (rack and towers) - FW version 1.96

  - iDRAC7 all models - FW version 1.46.45");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62598");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/920038");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:dell:idrac6",
                     "cpe:/a:dell:idrac7");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = infos["version"];

if (cpe =~ "^cpe:/a:dell:idrac6") {
  if (version_is_less(version: version, test_version: "1.96")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.96");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/a:dell:idrac7") {
  if (version_is_less(version: version, test_version: "1.46.45")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.46.45");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
