# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812753");
  script_version("2023-06-27T05:05:30+0000");
  script_cve_id("CVE-2018-6382");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-04 14:07:00 +0000 (Mon, 04 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-02-05 11:55:27 +0530 (Mon, 05 Feb 2018)");

  script_name("MantisBT 'sql' Parameter SQL Injection Vulnerability (Feb 2018) - Windows");

  script_tag(name:"summary", value:"MantisBT is prone to an SQL injection (SQLi) vulnerability.

  Note: The vendor disputes the significance of this report because server.php is intended to
  execute arbitrary SQL statements on behalf of authenticated users from 127.0.0.1, and the issue
  does not have an authentication bypass.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to insufficient validation of user supplied
  input via 'sql' parameter in via the 'vendor/adodb/adodb-php/server.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow local users to conduct SQL
  Injection attacks and if there is no configuration, the physical path address is leaked.");

  script_tag(name:"affected", value:"MantisBT version 2.10.0.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://archive.is/vs3Hy#selection-1317.21-1317.27");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"deprecated", value: TRUE);

  exit(0);
}

exit(66);