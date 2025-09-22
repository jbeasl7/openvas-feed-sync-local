# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801613");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-10-28 11:50:37 +0200 (Thu, 28 Oct 2010)");
  script_cve_id("CVE-2010-3494", "CVE-2009-5012", "CVE-2009-5013", "CVE-2009-5011");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("pyftpdlib FTP Server Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://code.google.com/p/pyftpdlib/issues/detail?id=100");
  script_xref(name:"URL", value:"http://code.google.com/p/pyftpdlib/issues/detail?id=104");
  script_xref(name:"URL", value:"http://code.google.com/p/pyftpdlib/issues/detail?id=105");
  script_xref(name:"URL", value:"http://code.google.com/p/pyftpdlib/issues/detail?id=114");
  script_xref(name:"URL", value:"http://code.google.com/p/pyftpdlib/issues/detail?id=119");
  script_xref(name:"URL", value:"http://code.google.com/p/pyftpdlib/source/browse/trunk/HISTORY");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("FTP");
  script_dependencies("gb_pyftpdlib_detect.nasl");
  script_mandatory_keys("pyftpdlib/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a denial of service.");
  script_tag(name:"affected", value:"ftpserver.py in pyftpdlib before 0.5.2");
  script_tag(name:"insight", value:"- Race condition in the FTPHandler class allows remote attackers to cause a
    denial of service by establishing and then immediately closing a TCP
    connection.

  - Improper permission check for the NLST command allows remote authenticated
    users to bypass intended access restrictions and list the root directory via
    an FTP session.

  - Memory leak in the on_dtp_close function allows remote authenticated users
    to cause a denial of service by sending a QUIT command during a data transfer.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to pyftpdlib version 0.5.2 or later.");
  script_tag(name:"summary", value:"pyftpdlib FTP server is prone to multiple vulnerabilities.");

  script_xref(name:"URL", value:"http://code.google.com/p/pyftpdlib/downloads/list");
  exit(0);
}


include("version_func.inc");

ver = get_kb_item("pyftpdlib/Ver");

if(ver != NULL)
{
  if(version_is_less(version:ver, test_version:"0.5.2")) {
     report = report_fixed_ver(installed_version:ver, fixed_version:"0.5.2");
     security_message(port: 0, data: report);
  }
}
