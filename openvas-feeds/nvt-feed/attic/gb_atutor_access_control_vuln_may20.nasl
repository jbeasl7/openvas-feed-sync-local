# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127214");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2022-10-06 11:49:35 +0000 (Thu, 06 Oct 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-15 18:15:00 +0000 (Fri, 15 Apr 2022)");

  script_cve_id("CVE-2021-43498");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("ATutor <= 2.2.4 Access Control Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"Atutor is prone to an access control vulnerability.

  This VT has been deprecated and merged into the VT 'ATutor <= 2.2.4 Multiple Vulnerabilities' (OID:
  1.3.6.1.4.1.25623.1.0.127055).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"Weak password reset hash in password_reminder.php lead to
  access control vulnerability.");

  script_tag(name:"affected", value:"Atutor version 2.2.4 and prior.");

  script_tag(name:"solution", value:"No solution was made available by the vendor.

  Note: The product is End of Life (EOL) and will not receive updates anymore.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/157563/ATutor-LMS-2.2.4-Weak-Password-Reset-Hash.html");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit( 66 );
