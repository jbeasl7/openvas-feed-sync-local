# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903020");
  script_version("2025-01-17T05:37:18+0000");
  script_cve_id("CVE-2012-1993", "CVE-2012-0135");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-04-25 13:28:29 +0530 (Wed, 25 Apr 2012)");
  script_name("HP System Management Homepage (SMH) Multiple Unspecified Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43012/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53121");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026925");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/522374");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to multiple unspecified errors, which allows
  attackers to gain sensitive information or cause denial of service via unknown vectors.");

  script_tag(name:"solution", value:"Update tp version 7.0 or later.");

  script_tag(name:"summary", value:"HP System Management Homepage (SMH) is prone to multiple
  unspecified vulnerabilities.

  This VT has been deprecated and merged into the VT 'HP System Management Homepage (SMH) Multiple Vulnerabilities (HPSBMU02764)'
  (OID: 1.3.6.1.4.1.25623.1.0.802758)");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain sensitive
  information or cause denial of service condition.");

  script_tag(name:"affected", value:"HP SMH prior to version 7.0.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
