# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818233");
  script_version("2024-06-13T05:05:46+0000");
  script_cve_id("CVE-2021-29424");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-08 13:52:00 +0000 (Tue, 08 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-04-07 03:09:24 +0000 (Wed, 07 Apr 2021)");
  script_name("Fedora: Security Advisory for perl-Net-Netmask (FEDORA-2021-3d96cfe6a3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2021-3d96cfe6a3");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CBJVLXJSWN6DKSF5ADUEERI6M23R3GGP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-Net-Netmask'
  package(s) announced via the FEDORA-2021-3d96cfe6a3 advisory.

  This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Net::Netmask parses and understands IPv4 and IPv6 CIDR blocks.
There are also functions to insert a network block into a table and then later look up
 network blocks by an IP address using that table.");

  script_tag(name:"affected", value:"'perl-Net-Netmask' package(s) on Fedora 34.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);