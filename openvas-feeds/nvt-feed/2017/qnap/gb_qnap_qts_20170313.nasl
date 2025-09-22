# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140219");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2017-03-24 12:56:10 +0100 (Fri, 24 Mar 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-5227", "CVE-2017-6361", "CVE-2017-6360", "CVE-2017-6359");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS < 4.2.4 Build 20170313 Multiple Vulnerabilities - Version Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2017-5227: Local users cat obtain sensitive Domain Administrator password information by
  reading data in an XOR format within the /etc/config/uLinux.conf configuration file.

  - SQL injection, command injection, heap overflow, cross-site scripting, and three stack overflow
  vulnerabilities

  - CVE-2017-6361, CVE-2017-6360, CVE-2017-6359: Command injection

  - Access control vulnerability that would incorrectly restrict authorized user access to resources.

  - Two stack overflow vulnerabilities that could be exploited to execute malicious codes reported

  - Clickjacking vulnerability that could be exploited to trick users into clicking malicious links

  - Missing HttpOnly Flag From Cookie vulnerability that could be exploited to steal session cookies.

  - SNMP Agent Default Community Name vulnerability that could be exploited to gain access to the
  system using the default community string.

  - NMP credentials in clear text vulnerability that could be exploited to steal user credentials.

  - LDAP anonymous directory access vulnerability that could be exploited to allow anonymous
  connections.");

  script_tag(name:"affected", value:"QNAP QTS version prior to 4.2.4 Build 20170313.");

  script_tag(name:"solution", value:"Update to version 4.2.4 Build 20170313 or later.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20170706142207/https://www.qnap.com/en/support/con_show.php?cid=113");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97059");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

build = get_kb_item( "qnap/nas/qts/build" );

if ( version_is_less( version:version, test_version:"4.2.4" ) ) {
  report = report_fixed_ver( installed_version:version, installed_build:build, fixed_version:"4.2.4", fixed_build:"20170313" );
  security_message( port:0, data:report );
  exit( 0 );
}

if ( version_is_equal( version:version, test_version:"4.2.4" ) &&
          ( ! build || version_is_less( version:build, test_version:"20170313" ) ) ) {
  report = report_fixed_ver( installed_version:version, installed_build:build, fixed_version:"4.2.4", fixed_build:"20170313" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
