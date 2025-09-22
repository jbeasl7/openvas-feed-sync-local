# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803343");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2011-5060", "CVE-2011-4114", "CVE-2011-3597", "CVE-2011-2939",
                "CVE-2011-2728");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-03-27 11:15:50 +0530 (Wed, 27 Mar 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Active Perl Modules Multiple Vulnerabilities - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_perl_detect_win.nasl");
  script_mandatory_keys("ActivePerl/Ver");

  script_xref(name:"URL", value:"http://search.cpan.org/dist/Digest/Digest.pm");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49911");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=731246");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=753955");
  script_xref(name:"URL", value:"https://rt.cpan.org/Public/Bug/Display.html?id=69560");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause an affected
  application to crash or execute arbitrary perl code.");

  script_tag(name:"affected", value:"Active Perl PAR module before 1.003

  Active Perl Digest module before 1.17

  Active Perl Encode module before 2.44

  Active Perl PAR::Packer module before 1.012");

  script_tag(name:"insight", value:"The flaws are due to

  - an error in par_mktmpdir function in the 'PAR::Packer' and 'PAR' modules
    creates temporary files in a directory with a predictable name without
    verifying ownership and permissions of this directory.

  - the 'Digest->new()' function not properly sanitising input before using it
    in an 'eval()' call, which can be exploited to inject and execute arbitrary
    perl code.

  - off-by-one error in the decode_xs function in Unicode/Unicode.xs in the
    'Encode' module.

  - An error within the 'File::Glob::bsd_glob()' function when handling the
    GLOB_ALTDIRFUNC flag can be exploited to cause an access violation and
    potentially execute arbitrary code.");

  script_tag(name:"summary", value:"Active Perl is prone to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Perl 5.14.2 or later.

  Upgrade to Active Perl PAR module version 1.003 or later.

  Upgrade to Active Perl Digest module version 1.17 or later.

  Upgrade to Active Perl Encode module version 2.44 or later.

  Upgrade Active Perl PAR::Packer module version 1.012 or later.");

  script_tag(name:"qod", value:"30");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:perl:perl";

include( "host_details.inc" );
include( "version_func.inc" );

## Perl Digest and Perl Encode modules are the default modules in perl
## Test for the perl versions < 5.14.2, because all perl versions are
## having Digest and Encode modules < 1.17 and 2.44 respectively

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "5.14.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.14.2", install_path: location );
  security_message(port: 0, data: report);
  exit( 0 );
}

exit( 99 );
