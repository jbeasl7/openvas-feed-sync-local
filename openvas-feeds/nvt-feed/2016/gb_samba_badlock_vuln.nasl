# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807646");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-2118", "CVE-2015-5370", "CVE-2016-2110", "CVE-2016-2111",
                "CVE-2016-2112", "CVE-2016-2113", "CVE-2016-2114", "CVE-2016-2115",
                "CVE-2016-0128");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-27 17:17:00 +0000 (Fri, 27 Sep 2019)");
  script_tag(name:"creation_date", value:"2016-04-14 14:39:10 +0530 (Thu, 14 Apr 2016)");
  script_name("Samba Badlock Critical Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_xref(name:"URL", value:"http://badlock.org/");
  script_xref(name:"URL", value:"http://thehackernews.com/2016/03/windows-samba-vulnerability.html");

  script_tag(name:"summary", value:"Samba is prone to badlock vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - multiple errors in DCE-RPC code

  - a spoofing Vulnerability in NETLOGON

  - the LDAP implementation did not enforce integrity protection for LDAP connections

  - the SSL/TLS certificates are not validated in certain connections

  - not enforcing Server Message Block (SMB) signing for clients using the SMB1 protocol

  - an integrity protection for IPC traffic is not enabled by default

  - the MS-SAMR and MS-LSAD protocol implementations mishandle DCERPC connections

  - an error in the implementation of NTLMSSP authentication");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  leads to Man-in-the-middle (MITM) attacks, to causes denial of service, to spoof
  and to obtain sensitive session information.");

  script_tag(name:"affected", value:"Samba versions 3.0.x through 4.4.1.

  NOTE: Samba versions 4.2.11, 4.3.8 are not affected");

  script_tag(name:"solution", value:"Upgrade to samba version 4.2.11, or 4.3.8,
  or 4.4.2, or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
loc = infos["location"];

# nb: Below versions are not vulnerable
if( vers == "4.2.11" || vers == "4.3.8" || vers == "4.4.2" )
  exit( 99 );

if( vers =~ "^[34]\." ) {
  if( version_is_less( version:vers, test_version:"4.4.2" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"4.2.11 or 4.3.8 or 4.4.2, or later", install_path:loc );
    security_message( data:report, port:port );
    exit( 0 );
  }
}

exit( 99 );
