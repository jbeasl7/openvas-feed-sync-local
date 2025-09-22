# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140297");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-08-15 08:57:34 +0700 (Tue, 15 Aug 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-6359", "CVE-2017-6360", "CVE-2017-6361");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Multiple Arbitrary Command Execution Vulnerabilities (Aug 2017) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple vulnerabilities.

  This VT was deprecated since it is a duplicate of QNAP QTS < 4.2.4 Build 20170313
  Multiple Vulnerabilities - Active Check (OID: 1.3.6.1.4.1.25623.1.0.140238)");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"QNAP QTS is prone to multiple vulnerabilities:

  - CVE-2017-6359: Command Injection in utilRequest.cgi cancel_trash_recovery 'pid'

  - CVE-2017-6360: Command Injection in userConfig.cgi cloudPersonalSmtp 'hash'

  - CVE-2017-6361: Command Injection in authLogin.cgi 'reboot_notice_msg'");

  script_tag(name:"affected", value:"QNAP QTS prior to 4.2.4 Build 20170313.");

  script_tag(name:"solution", value:"Update to QNAP QTS 4.2.4 Build 20170313 or newer.");

  script_xref(name:"URL", value:"https://www.qnap.com/en-us/releasenotes/");
  script_xref(name:"URL", value:"https://sintonen.fi/advisories/qnap-qts-multiple-rce-vulnerabilities.txt");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
