# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:atmail:atmail";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100818");
  script_version("2024-03-04T14:37:58+0000");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2010-09-22 16:24:51 +0200 (Wed, 22 Sep 2010)");
  script_cve_id("CVE-2010-4930");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Atmail 'MailType' Parameter Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43377");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/513890");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("atmail_detect.nasl");
  script_mandatory_keys("Atmail/installed");

  script_tag(name:"solution", value:"Reports indicate that this issue has been fixed by the vendor, this has
  not been confirmed. Please contact the vendor for more information.");

  script_tag(name:"summary", value:"Atmail is prone to a cross-site scripting vulnerability because it fails
  to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary JavaScript code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker to
  steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"Atmail 6.1.9 is vulnerable. Prior versions may also be affected.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version: vers, test_version: "6.2.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"6.2.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
