# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107293");
  script_version("2025-01-17T05:37:18+0000");
  script_cve_id("CVE-2018-1000024");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2018-02-07 13:28:30 +0100 (Wed, 07 Feb 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Squid Proxy Cache Security Update Advisory (SQUID-2018:1) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"Squid is vulnerable to denial of service attack when
  processing ESI responses.

  This VT has been deprecated and merged into the VT 'Squid Proxy Cache Security Update Advisory SQUID-2018:1'
  (OID:1.3.6.1.4.1.25623.1.0.107294)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to unrelated changes Squid-3.5 has become vulnerable
  to some regular ESI server responses also triggering this issue. This problem is limited to
  the Squid custom ESI parser.");

  script_tag(name:"impact", value:"This problem allows a remote server delivering certain ESI
  response syntax to trigger a denial of service for all clients accessing the Squid service.");

  script_tag(name:"affected", value:"Squid 3.x -> 3.5.27, Squid 4.x -> 4.0.22.");

  script_tag(name:"solution", value:"Upgrade to 4.0.23 or later. Patches are available, please
  see the references for details.");

  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2018_1.txt");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
