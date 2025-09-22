# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142472");
  script_version("2024-04-04T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-04-04 05:05:25 +0000 (Thu, 04 Apr 2024)");
  script_tag(name:"creation_date", value:"2019-05-31 02:16:11 +0000 (Fri, 31 May 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-20 15:32:00 +0000 (Mon, 20 May 2019)");

  script_cve_id("CVE-2019-11809");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Joomla! < 3.9.6 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"deprecated", value:TRUE);

  script_tag(name:"summary", value:"This VT has been deprecated due to the CVE already being
  covered by another script('Joomla 1.7.0 <= 3.9.5 XSS Vulnerability') with OID '1.3.6.1.4.1.25623.1.0.112586'.
  Joomla! is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The debug views of com_users do not properly escape user supplied data, which
  leads to a potential XSS attack vector.");

  script_tag(name:"affected", value:"Joomla! CMS versions 1.7.0 through 3.9.5.");

  script_tag(name:"solution", value:"Update to version 3.9.6 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre.html");

  exit(0);
}

exit(66);
