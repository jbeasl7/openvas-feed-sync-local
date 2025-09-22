# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800907");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-07-18 09:37:41 +0200 (Sat, 18 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2354", "CVE-2009-2355", "CVE-2009-2356");
  script_name("NullLogic Groupware <= 1.2.7 Multiple Vulnerabilities - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51591");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35606");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51592");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51593");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1817");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/504737/100/0/threaded");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary
  SQL queries in the context of affected application, and can cause buffer overflow or
  a denial of service.");

  script_tag(name:"affected", value:"NullLogic Groupware 1.2.7 and prior.");

  script_tag(name:"insight", value:"Multiple flaws exist because:

  - The 'auth_checkpass' function in the login page does not validate the input passed
  into the username parameter.

  - An error in the 'fmessagelist' function in the forum module when processing a group
  name containing a non-numeric string or is an empty string.

  - Multiple stack-based buffer overflows occurs in the 'pgsqlQuery' function while
  processing malicious input to POP3, SMTP or web component that triggers a long SQL query
  when PostgreSQL is used.");

  script_tag(name:"solution", value:"No known solution was made available for at least one
  year since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"NullLogic Groupware is prone to multiple
  vulnerabilities.

  This VT has been deprecated and merged into the VT 'NullLogic Groupware <= 1.2.7 Multiple
  Vulnerabilities' (OID: 1.3.6.1.4.1.25623.1.0.800906).");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
