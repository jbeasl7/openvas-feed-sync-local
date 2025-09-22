# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mit:kerberos";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800433");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2010-01-20 08:21:11 +0100 (Wed, 20 Jan 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4212");
  script_name("MIT Kerberos5 Multiple Integer Underflow Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_kerberos5_ssh_login_detect.nasl");
  script_mandatory_keys("mit/kerberos5/detected");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=545015");
  script_xref(name:"URL", value:"http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2009-004.txt");
  script_xref(name:"URL", value:"http://web.mit.edu/kerberos/advisories/2009-004-patch_1.6.3.txt");
  script_xref(name:"URL", value:"http://web.mit.edu/kerberos/advisories/2009-004-patch_1.7.txt");

  script_tag(name:"affected", value:"MIT Kerberos5 versions 1.3 through 1.6.3, and version 1.7.");

  script_tag(name:"insight", value:"Multiple Integer Underflow due to errors within the 'AES' and 'RC4'
  decryption functionality in the crypto library in MIT Kerberos when processing ciphertext with a
  length that is too short to be valid.");

  script_tag(name:"summary", value:"MIT Kerberos5 is prone to multiple integer underflow vulnerabilities.");

  script_tag(name:"solution", value:"Apply the patch mentioned in the references.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to cause a Denial of
  Service (DoS) or possibly execute arbitrary code.");

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

if( version_in_range( version: version, test_version: "1.3", test_version2: "1.6.3" ) ||
  version_is_equal( version: version, test_version: "1.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "Apply the referenced patch", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
