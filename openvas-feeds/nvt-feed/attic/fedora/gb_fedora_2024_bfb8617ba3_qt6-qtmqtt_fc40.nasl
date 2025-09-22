# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886900");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2024-36048");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2024-06-07 06:34:24 +0000 (Fri, 07 Jun 2024)");
  script_name("Fedora: Security Advisory for qt6-qtmqtt (FEDORA-2024-bfb8617ba3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-bfb8617ba3");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZPHAI3DKDCIU6XLNS6PV6GFS2PHH3GZM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qt6-qtmqtt'
  package(s) announced via the FEDORA-2024-bfb8617ba3 advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MQTT is a machine-to-machine (M2M) protocol utilizing the publish-and-subscribe
paradigm, and provides a channel with minimal communication overhead.
The Qt MQTT module provides a standard compliant implementation of the MQTT
protocol specification. It enables applications to act as telemetry displays
and devices to publish telemetry data.");

  script_tag(name:"affected", value:"'qt6-qtmqtt' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
