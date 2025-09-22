# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886631");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2024-27982");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2024-05-27 10:43:44 +0000 (Mon, 27 May 2024)");
  script_name("Fedora: Security Advisory for uxplay (FEDORA-2024-f83b123d63)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-f83b123d63");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/QJAKA33NJCI3XLQS2K36DRCUMWIFFYVU");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'uxplay'
  package(s) announced via the FEDORA-2024-f83b123d63 advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An AirPlay2 Mirror and AirPlay2 Audio (but not Video) server that provides
screen-mirroring (with audio) of iOS/MacOS clients in a display window on
the server host (which can be shared using a screen-sharing application),
Apple Lossless Audio (ALAC) (e.g.,iTunes) can be streamed from client to
server in non-mirror mode.");

  script_tag(name:"affected", value:"'uxplay' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
