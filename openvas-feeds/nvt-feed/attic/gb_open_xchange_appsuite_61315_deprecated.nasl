# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112179");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2019-06-19 12:31:11 +0200 (Wed, 19 Jun 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2019-7158");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Open-Xchange (OX) AppSuite Improper Access Control Vulnerability (Bug ID 61315)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"Open-Xchange (OX) AppSuite is prone to an improper access control vulnerability.

  This VT has been deprecated and replaced by the VT 'Open-Xchange (OX) AppSuite Access Control Vulnerability (Bug ID 61315)' (OID: 1.3.6.1.4.1.25623.1.0.142235).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In case users did choose not to 'stay signed in' or the operator disabled that functionality,
  cookies are maintained for a 'session' lifetime to make sure they expire after the browser session has ended.
  Using 'reload' on the existing browser session led to the impression that the session is already terminated as the login
  screen would be shown afterwards. However, those cookies are maintained by the browser for the remainder of the session until
  termination of the browser tab or window.");

  script_tag(name:"impact", value:"Users could get the incorrect impression that their session has been terminated
  after reloading the browser window. In fact, the credentials for authentication (cookies) were maintained and
  other users with physical access to the browser could re-use them to execute API calls and access other users data.");

  script_tag(name:"affected", value:"All Open-Xchange AppSuite versions before 7.8.3-rev53, 7.8.4 before rev51, 7.10.0 before rev25 and 7.10.1 before rev7.");

  script_tag(name:"solution", value:"Update to version 7.8.3-rev53, 7.8.4-rev51, 7.10.0-rev25 or 7.10.1-rev7 respectively.");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
