# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801618");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-10-28 11:50:37 +0200 (Thu, 28 Oct 2010)");
  script_cve_id("CVE-2007-6738");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("pyftpdlib FTP Server Information Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://code.google.com/p/pyftpdlib/source/browse/trunk/HISTORY");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("FTP");
  script_dependencies("gb_pyftpdlib_detect.nasl");
  script_mandatory_keys("pyftpdlib/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain potentially sensitive
  information about the number of in-progress data connections.");
  script_tag(name:"affected", value:"ftpserver.py in pyftpdlib before 0.1.1");
  script_tag(name:"insight", value:"The flaw exists because pyftpdlib does not choose a random value for the port
  associated with the PASV command, which makes it easier for remote attackers
  to obtain potentially sensitive information about the number of in-progress
  data connections by reading the response to this command.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to pyftpdlib version 0.5.2 or later.");
  script_tag(name:"summary", value:"pyftpdlib FTP server is prone to an information disclosure vulnerability.");

  script_xref(name:"URL", value:"http://code.google.com/p/pyftpdlib/downloads/list");
  exit(0);
}


include("version_func.inc");

ver = get_kb_item("pyftpdlib/Ver");

if(ver != NULL)
{
  if(version_is_less(version:ver, test_version:"0.1.1")) {
     report = report_fixed_ver(installed_version:ver, fixed_version:"0.1.1");
     security_message(port: 0, data: report);
  }
}
