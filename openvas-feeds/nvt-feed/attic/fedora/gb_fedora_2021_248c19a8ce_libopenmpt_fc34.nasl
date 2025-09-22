# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818212");
  script_version("2025-04-24T05:40:01+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:01 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2021-04-06 03:17:24 +0000 (Tue, 06 Apr 2021)");
  script_name("Fedora: Security Advisory for libopenmpt (FEDORA-2021-248c19a8ce)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2021-248c19a8ce");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2XPU2VHR2OYFRDTVOFZEOORAYNU3Q6IH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libopenmpt'
  package(s) announced via the FEDORA-2021-248c19a8ce advisory.

  This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libopenmpt is a cross-platform C++ and C library to decode tracked music
files (modules) into a raw PCM audio stream.

libopenmpt is based on the player code of the OpenMPT project (Open
ModPlug Tracker). In order to avoid code base fragmentation, libopenmpt is
developed in the same source code repository as OpenMPT.");

  script_tag(name:"affected", value:"'libopenmpt' package(s) on Fedora 34.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
