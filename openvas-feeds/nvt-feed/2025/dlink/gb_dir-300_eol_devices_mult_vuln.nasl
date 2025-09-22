# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dir-300_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.134002");
  script_version("2025-08-08T15:44:57+0000");
  script_tag(name:"last_modification", value:"2025-08-08 15:44:57 +0000 (Fri, 08 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-16 12:24:27 +0000 (Fri, 16 May 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-07 20:54:20 +0000 (Wed, 07 Aug 2024)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  # nb: Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs / to
  #     avoid too large diffs when adding a new CVE.
  script_cve_id("CVE-2011-4723",
                "CVE-2013-7471",
                "CVE-2013-10048",
                "CVE-2013-10050",
                "CVE-2013-10069",
                "CVE-2024-0717",
                "CVE-2024-41616"
               );

  script_name("D-Link DIR-300 Multiple Vulnerabilities (2011 - 2024)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-300 devices are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2011-4723: disclosure of sensitive information

  - CVE-2013-7471: Command Injection via shell metacharacters in the NewInternalClient,
  NewExternalPort, or NewInternalPort element of a SOAP POST request.

  - CVE-2013-10048, CVE-2013-10069: OS command injection vulnerability due to improper input
  handling in the unauthenticated command.php endpoint

  - CVE-2013-10050: OS command injection via the authenticated tools_vct.xgi CGI endpoint

  - CVE-2024-0717: Information disclosure via manipulation of /devinfo arguments

  - CVE-2024-41616: Hard-coded credentials in the Telnet service");

  script_tag(name:"affected", value:"D-Link DIR-300 devices in all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: Vendor states that DIR-300 Rev. Ax and Bx devices reached End-of-Support Date in 2010,
  Rev. Cx and Dx in 2020, they are no longer supported, and firmware development has ceased.
  See vendor advisory for further recommendations.");

  script_xref(name:"URL", value:"https://global.ptsecurity.com/analytics/threatscape/pt-2011-30");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/24453");
  script_xref(name:"URL", value:"https://web.archive.org/web/20131022221648/http://www.s3cur1ty.de/m1adv2013-003");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/27044");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/27528");
  script_xref(name:"URL", value:"https://web.archive.org/web/20140830203110/http://www.s3cur1ty.de/m1adv2013-014");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/27428");
  script_xref(name:"URL", value:"https://github.com/999zzzzz/D-Link");
  script_xref(name:"URL", value:"https://github.com/LYaoBoL/IOTsec/blob/main/D-Link/DIR300/D-Link300.md");
  script_xref(name:"URL", value:"https://github.com/LYaoBoL/IOTsec/blob/main/D-Link/DIR300/CVE-2024-41616");
  script_xref(name:"URL", value:"https://service.dlink.co.in/resources/EOL-Products-Without-Service.pdf");
  script_xref(name:"URL", value:"https://legacy.us.dlink.com/");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

report = report_fixed_ver( installed_version:version, fixed_version:"None" );
security_message( port:0, data:report );
exit( 0 );
