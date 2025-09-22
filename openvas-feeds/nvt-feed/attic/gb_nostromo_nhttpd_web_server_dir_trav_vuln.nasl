# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802010");
  script_version("2025-06-05T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-06-05 05:40:56 +0000 (Thu, 05 Jun 2025)");
  script_tag(name:"creation_date", value:"2011-03-22 08:43:18 +0100 (Tue, 22 Mar 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2011-0751");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nazgul Nostromo nhttpd < 1.9.4 Directory Traversal Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web Servers");

  script_tag(name:"summary", value:"Nazgul Nostromo nhttpd is prone to a directory traversal
  vulnerability.

  This VT has been deprecated as a duplicate of the VT 'Nazgul Nostromo nhttpd < 1.9.4 RCE /
  Directory Traversal Vulnerability - Active Check' (OID: 1.3.6.1.4.1.25623.1.0.103119).");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to an error in validating '%2f..' sequences in
  the URI causing attackers to read arbitrary files.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to perform directory
  traversal attacks and read arbitrary files on the affected application.");

  script_tag(name:"affected", value:"Nazgul Nostromo nhttpd prior to version 1.9.4.");

  script_tag(name:"solution", value:"Update to version 1.9.4 or later.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210127125244/http://www.securityfocus.com/bid/46880");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121063309/http://www.securityfocus.com/archive/1/517026");
  script_xref(name:"URL", value:"https://www.redteam-pentesting.de/en/advisories/rt-sa-2011-001/");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
