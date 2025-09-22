# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mit:kerberos";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800441");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2010-01-22 09:23:45 +0100 (Fri, 22 Jan 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3295");
  script_name("MIT Kerberos5 KDC Cross Realm Referral DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_kerberos5_ssh_login_detect.nasl");
  script_mandatory_keys("mit/kerberos5/detected");

  script_xref(name:"URL", value:"http://web.mit.edu/kerberos/advisories/2009-003-patch.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37486");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3652");
  script_xref(name:"URL", value:"http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2009-003.txt");

  script_tag(name:"affected", value:"MIT Kerberos5 versions prior to 1.7.1.");

  script_tag(name:"insight", value:"The flaw is caused by a NULL pointer dereference error in the KDC cross-realm
  referral processing implementation, which could allow an unauthenticated remote attacker to cause KDC to crash.");

  script_tag(name:"summary", value:"MIT Kerberos5 is prone to a Denial of Service (DoS) vulnerability.");

  script_tag(name:"solution", value:"Update to version 1.7.1 or later.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to cause a DoS.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.7.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.7.1", install_path: location );
  security_message(port: 0, data: report);
  exit( 0 );
}

exit( 99 );
