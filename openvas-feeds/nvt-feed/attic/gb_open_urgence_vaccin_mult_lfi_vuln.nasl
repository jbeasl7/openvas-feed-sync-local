# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800764");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-05-05 15:59:12 +0200 (Wed, 05 May 2010)");
  script_cve_id("CVE-2010-1466", "CVE-2010-1467");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Openurgence Vaccin 1.03 Multiple File Inclusion Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"insight", value:"Input passed to the parameter 'path_om' in various files and to
  the parameter 'dsn[phptype]' in 'scr/soustab.php' are not properly verified before being used to
  include files.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"summary", value:"Openurgence Vaccin is prone multiple file inclusion
  vulnerabilities.

  This VT has been deprecated and replaced by the VT 'openUrgence Vaccin Multiple Remote File Include Vulnerabilities'
  (OID: 1.3.6.1.4.1.25623.1.0.100627).");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain
  sensitive information or compromise the application and the underlying system.");

  script_tag(name:"affected", value:"Openurgence Vaccin version 1.03.");

  script_tag(name:"deprecated", value:TRUE);

  script_xref(name:"URL", value:"http://secunia.com/advisories/39400");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39412");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57815");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/12193");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

exit(66);
