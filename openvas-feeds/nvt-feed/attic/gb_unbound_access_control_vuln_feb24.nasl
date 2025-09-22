# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124618");
  script_version("2025-01-24T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-24 05:37:33 +0000 (Fri, 24 Jan 2025)");
  script_tag(name:"creation_date", value:"2024-03-08 07:07:53 +0000 (Fri, 08 Mar 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-23 17:41:40 +0000 (Thu, 23 Jan 2025)");

  script_cve_id("CVE-2024-1488");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Unbound DNS Resolver < 1.19.1-2.fc40 Access Control Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");

  script_tag(name:"summary", value:"Unbound DNS Resolver is prone to an access control
  vulnerability.

  This VT was deprecated as it has been determined that this is not a software flaw in the product
  itself but an issue in Red Hat (RHEL) and derivates (e.g. Fedora) specific packaging of the
  product and for which various more reliable Local Security Checks (LSCs) already exists.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unbound allows by default not only members of unbound group to
  change any unbound runtime configuration, but any process able to connect over localhost to port
  8953, can change configuration of unbound.service.");

  script_tag(name:"affected", value:"Unbound DNS Resolver packages on specific Red Hat (RHEL) and
  derivates (e.g. Fedora).");

  script_tag(name:"solution", value:"Check for available updates from the packaging provider.");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264183");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-f858b5bb4e");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
