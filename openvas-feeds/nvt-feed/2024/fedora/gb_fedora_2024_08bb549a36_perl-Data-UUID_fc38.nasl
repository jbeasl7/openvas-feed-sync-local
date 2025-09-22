# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886339");
  script_version("2024-04-18T05:05:33+0000");
  script_cve_id("CVE-2013-4184");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-04-18 05:05:33 +0000 (Thu, 18 Apr 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-17 18:42:20 +0000 (Tue, 17 Dec 2019)");
  script_tag(name:"creation_date", value:"2024-03-28 02:11:33 +0000 (Thu, 28 Mar 2024)");
  script_name("Fedora: Security Advisory for perl-Data-UUID (FEDORA-2024-08bb549a36)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-08bb549a36");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/MATNG5VP46SXJB2JHAI2LXPUXCYUOYPE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-Data-UUID'
  package(s) announced via the FEDORA-2024-08bb549a36 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This module provides a framework for generating v3 UUIDs (Universally Unique
Identifiers, also known as GUIDs (Globally Unique Identifiers). A UUID is 128
bits long, and is guaranteed to be different from all other UUIDs/GUIDs
generated until 3400 CE.

UUIDs were originally used in the Network Computing System (NCS) and later in
the Open Software Foundation&#39, s (OSF) Distributed Computing Environment.
Currently many different technologies rely on UUIDs to provide unique identity
for various software components. Microsoft COM/DCOM for instance, uses GUIDs
very extensively to uniquely identify classes, applications and components
across network-connected systems.

The algorithm for UUID generation, used by this extension, is described in the
Internet Draft 'UUIDs and GUIDs' by Paul J. Leach and Rich Salz (see RFC 4122).
It provides a reasonably efficient and reliable framework for generating UUIDs
and supports fairly high allocation rates - 10 million per second per machine -
and therefore is suitable for identifying both extremely short-lived and very
persistent objects on a given system as well as across the network.

This module provides several methods to create a UUID. In all methods,
<namespace> is a UUID and <name> is a free form string.");

  script_tag(name:"affected", value:"'perl-Data-UUID' package(s) on Fedora 38.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC38") {

  if(!isnull(res = isrpmvuln(pkg:"perl-Data-UUID", rpm:"perl-Data-UUID~1.227~1.fc38", rls:"FC38"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);