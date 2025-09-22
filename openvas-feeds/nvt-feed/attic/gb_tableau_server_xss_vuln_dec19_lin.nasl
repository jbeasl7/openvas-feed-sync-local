# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114163");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2019-12-13 16:06:07 +0100 (Fri, 13 Dec 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-12 20:07:00 +0000 (Thu, 12 Dec 2019)");

  script_cve_id("CVE-2019-19719");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tableau Server XSS Vulnerability (ADV-2019-047) - Deprecated");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");

  script_xref(name:"URL", value:"https://community.tableau.com/s/news/a0A4T000001v3TIUAY/important-adv2019047-open-redirect-on-embeddedauthredirect-page");

  script_tag(name:"summary", value:"Tableau Server is prone to a cross-site scripting (XSS)
  vulnerability.

  This VT has been deprecated and merged into the VT 'Tableau Server XSS Vulnerability (ADV-2019-047)' (OID:
  1.3.6.1.4.1.25623.1.0.114164)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Tableau Server on Windows and Linux allows XSS via the
  embeddedAuthRedirect page. The server fails to properly validate the path that is presented on
  this redirect page.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to initiate a
  reflected cross-site scripting operation via JavaScript, which runs in the client context.
  Alternatively, a Tableau server user who clicks on a malicious link could be redirected to an
  attacker-controlled location.");

  script_tag(name:"affected", value:"Tableau Server versions 10.3 through 2019.4.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
