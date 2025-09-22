# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800983");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-01-22 16:43:14 +0100 (Fri, 22 Jan 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4595", "CVE-2009-4596", "CVE-2009-4597");
  script_name("PHP Inventory Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37672");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54666");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54667");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/10370");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to include arbitrary
  HTML or web scripts in the scope of the browser and allows to obtain and manipulate sensitive information.");

  script_tag(name:"affected", value:"PHP Inventory version 1.2 and prior.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Input passed via the 'user_id' parameter to 'index.php' and via the 'sup_id'
    parameter is not properly sanitised before being used in an SQL query.

  - Input passed via the 'user' and 'pass' form field to 'index.php' is not
    properly sanitised before being used in an SQL query.");

  script_tag(name:"solution", value:"Update to PHP Inventory version 1.3.2 or later.");

  script_tag(name:"summary", value:"PHP inventory is prone to multiple vulnerabilities.

  This VT has been deprecated and replaced by the VT 'PHP Inventory 'user' and 'pass' Parameters SQL Injection Vulnerability' (OID: 1.3.6.1.4.1.25623.1.0.802534).");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
