# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112607");
  script_version("2024-04-04T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-04-04 05:05:25 +0000 (Thu, 04 Apr 2024)");
  script_tag(name:"creation_date", value:"2019-07-16 19:00:00 +0000 (Tue, 16 Jul 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-26 17:11:00 +0000 (Mon, 26 Aug 2019)");

  script_cve_id("CVE-2019-15324");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Ad Inserter Plugin < 2.4.22 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"The WordPress plugin 'Ad Inserter' is prone to an authenticated
  remote code execution (RCE) vulnerability.

  This VT has been deprecated as a duplicate of the VT 'WordPress Ad Inserter Plugin < 2.4.22 RCE
  Vulnerability' (OID:1.3.6.1.4.1.25623.1.0.113520).");

  script_tag(name:"insight", value:"The vulnerability stems from the use of the
  check_admin_referer() for authorization, when it was specifically designed to protect WordPress
  sites against cross-site request forgery (CSRF) exploits using nonces-one-time tokens used for
  blocking expired and repeated requests.

  Authenticated attackers who get their hands on a nonce can bypass the authorization checks powered
  by the check_admin_referer() function to access the debug mode provided by the Ad Inserter plugin.

  Once the attacker has a nonce at his disposal, he can immediately trigger the debugging feature
  and, even more dangerous, exploit the ad preview feature by sending a malicious payload containing
  arbitrary PHP code.");

  script_tag(name:"impact", value:"Successful exploitation would allow authenticated users
  (Subscribers and above) to execute arbitrary PHP code on websites using the plugin.");

  script_tag(name:"affected", value:"WordPress Ad Inserter plugin before version 2.4.22.");

  script_tag(name:"solution", value:"Update to version 2.4.22 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/ad-inserter/#developers");
  script_xref(name:"URL", value:"https://www.bleepingcomputer.com/news/security/critical-bug-in-wordpress-plugin-lets-hackers-execute-code/");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2019/07/critical-vulnerability-patched-in-ad-inserter-plugin/");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
