# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113382");
  script_version("2024-04-04T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-04-04 05:05:25 +0000 (Thu, 04 Apr 2024)");
  script_tag(name:"creation_date", value:"2019-05-06 13:23:11 +0000 (Mon, 06 May 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2019-11631");

  script_name("Moodle <= 3.6.3 File Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"Moodle is prone to a file upload vulnerability.

  This VT has been deprecated since this CVE has been withdrawn since further investigation showed
  that it was not a security issue.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Moodle allows remote authenticated administrators to execute
  arbitrary PHP code via a ZIP archive, containing a theme_*.php file, to
  repository/repository_ajax.php?action=upload and admin/tool/installaddon/index.php.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to execute
  arbitrary code on the target system.");

  script_tag(name:"affected", value:"Moodle through version 3.6.3.");

  script_tag(name:"solution", value:"No solution is required.

  Note: No vendor fix will be provided since further investigation showed that it was not a security
  issue.");

  script_xref(name:"URL", value:"http://pentest.com.tr/exploits/Moodle-3-6-3-Install-Plugin-Remote-Command-Execution.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/108119");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/46775");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);