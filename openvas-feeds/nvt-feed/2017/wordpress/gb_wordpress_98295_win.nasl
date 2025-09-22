# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108156");
  script_version("2025-01-17T15:39:18+0000");
  script_cve_id("CVE-2017-8295");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");
  script_tag(name:"creation_date", value:"2017-05-08 11:00:15 +0200 (Mon, 08 May 2017)");
  script_name("WordPress Password Reset CVE-2017-8295 Security Bypass Vulnerability - Windows");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41963/");
  script_xref(name:"URL", value:"https://exploitbox.io/vuln/WordPress-Exploit-4-7-Unauth-Password-Reset-0day-CVE-2017-8295.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98295");

  script_tag(name:"summary", value:"WordPress is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws exist because WordPress relies on the Host HTTP header for a password-reset e-mail message,
  which makes it easier for user-assisted remote attackers to reset arbitrary passwords by making a crafted wp-login.php?action=lostpassword
  request and then arranging for this e-mail to bounce or be resent, leading to transmission of the reset key to a mailbox on an
  attacker-controlled SMTP server. This is related to problematic use of the SERVER_NAME variable in wp-includes/pluggable.php in
  conjunction with the PHP mail function.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to bypass certain security restrictions to perform unauthorized actions.
  This may aid in further attacks.");

  script_tag(name:"affected", value:"WordPress versions 4.7.4 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.

  A workaround is to enable UseCanonicalName to enforce static SERVER_NAME value.");

  script_xref(name:"URL", value:"https://httpd.apache.org/docs/2.4/mod/core.html#usecanonicalname");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less_equal( version:vers, test_version:"4.7.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None" );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
