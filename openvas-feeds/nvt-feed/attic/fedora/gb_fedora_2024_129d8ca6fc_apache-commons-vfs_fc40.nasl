# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886099");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2024-1938", "CVE-2024-1939");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-19 20:20:25 +0000 (Thu, 19 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-03-08 02:18:42 +0000 (Fri, 08 Mar 2024)");
  script_name("Fedora: Security Advisory for apache-commons-vfs (FEDORA-2024-129d8ca6fc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-129d8ca6fc");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FMPE4QJKUXRHBENOFG6T5LVXWF7JLJZF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache-commons-vfs'
  package(s) announced via the FEDORA-2024-129d8ca6fc advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Commons VFS provides a single API for accessing various file systems.
It presents a uniform view of the files from various sources, such as
the files on local disk, on an HTTP server, or inside a Zip archive.

Some of the features of Commons VFS are:

  * A single consistent API for accessing files of different types.

  * Support for numerous file system types.

  * Caching of file information.  Caches information in-JVM, and
  optionally can cache remote file information on the local file
  system (replicator).

  * Event delivery.

  * Support for logical file systems made up of files from various file
  systems.

  * Utilities for integrating Commons VFS into applications, such as a
  VFS-aware ClassLoader and URLStreamHandlerFactory.

  * A set of VFS-enabled Ant tasks.");

  script_tag(name:"affected", value:"'apache-commons-vfs' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
