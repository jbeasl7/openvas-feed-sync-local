# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800237");
  script_version("2023-08-24T05:06:01+0000");
  script_tag(name:"last_modification", value:"2023-08-24 05:06:01 +0000 (Thu, 24 Aug 2023)");
  script_tag(name:"creation_date", value:"2009-02-11 16:51:00 +0100 (Wed, 11 Feb 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2008-6082");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TitanFTP Server < 6.26.631 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");

  script_tag(name:"summary", value:"TitanFTP Server is prone to a denial of service vulnerability.

  This VT was deprecated since it is a duplicate of Titan FTP Server < 6.26.631 Remote DoS
  Vulnerability (OID: 1.3.6.1.4.1.25623.1.0.900160).");

  script_tag(name:"impact", value:"Successful exploitation will cause a denial of service.");

  script_tag(name:"affected", value:"TitanFTP Server version prior to 6.26.631.");

  script_tag(name:"insight", value:"An error exists while processing the SITE WHO command by the
  FTP service which in turn causes extensive usages of CPU resources.");

  script_tag(name:"solution", value:"Upgrade to version 6.26.631 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32269");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31757");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/6753");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
