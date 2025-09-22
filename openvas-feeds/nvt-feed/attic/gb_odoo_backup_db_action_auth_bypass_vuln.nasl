# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812757");
  script_version("2025-04-10T05:39:36+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-04-10 05:39:36 +0000 (Thu, 10 Apr 2025)");
  script_tag(name:"creation_date", value:"2018-02-08 13:00:22 +0530 (Thu, 08 Feb 2018)");
  script_cve_id("CVE-2018-6620");

  script_name("Odoo 'Backup Database Action' Authentication Bypass Vulnerability");

  script_tag(name:"summary", value:"Odoo is prone to an authentication bypass vulnerability.

  This VT has been deprecated since CVE-2018-6620 has been rejected.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw exists as Odoo does not require authentication to be
  configured for a 'Backup Database' action.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to backup
  websites databases directly with no authenticated accounts.");

  script_tag(name:"solution", value:"No solution is required.

  Note: CVE-2018-6620 has been rejected.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");

  script_xref(name:"URL", value:"https://github.com/odoo/odoo/issues/25668");
  script_xref(name:"URL", value:"https://www.cnvd.org.cn/flaw/show/CNVD-2018-04841");

  # nb: Reject reasons:
  # - CVE-2018-6620 has been rejected
  # - It seems the code was also false positive prone as it checked for responses which are also
  #   there if the master password was set (which is also mandatory on newer Odoo versions)
  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
