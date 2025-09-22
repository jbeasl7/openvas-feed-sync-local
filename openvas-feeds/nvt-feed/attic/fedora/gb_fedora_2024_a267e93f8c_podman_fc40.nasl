# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886330");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2024-1753");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-18 15:15:41 +0000 (Mon, 18 Mar 2024)");
  script_tag(name:"creation_date", value:"2024-03-27 02:16:17 +0000 (Wed, 27 Mar 2024)");
  script_name("Fedora: Security Advisory for podman (FEDORA-2024-a267e93f8c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-a267e93f8c");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZVBSVZGVABPYIHK5HZM472NPGWMI7WXH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'podman'
  package(s) announced via the FEDORA-2024-a267e93f8c advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"podman (Pod Manager) is a fully featured container engine that is a simple
daemonless tool.  podman provides a Docker-CLI comparable command line that
eases the transition from other container engines and allows the management of
pods, containers and images.  Simply put: alias docker=podman.
Most podman commands can be run as a regular user, without requiring
additional privileges.

podman uses Buildah(1) internally to create container images.
Both tools share image (not container) storage, hence each can use or
manipulate images (but not containers) created by the other.

Manage Pods, Containers and Container Images
%{repo} Simple management tool for pods, containers and images");

  script_tag(name:"affected", value:"'podman' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
