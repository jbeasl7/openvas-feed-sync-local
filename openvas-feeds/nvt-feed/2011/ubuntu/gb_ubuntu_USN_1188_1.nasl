# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840719");
  script_cve_id("CVE-2011-1831", "CVE-2011-1832", "CVE-2011-1833", "CVE-2011-1834", "CVE-2011-1835", "CVE-2011-1836", "CVE-2011-1837");
  script_tag(name:"creation_date", value:"2011-08-12 13:49:01 +0000 (Fri, 12 Aug 2011)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1188-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|11\.04)");

  script_xref(name:"Advisory-ID", value:"USN-1188-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1188-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ecryptfs-utils' package(s) announced via the USN-1188-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vasiliy Kulikov and Dan Rosenberg discovered that eCryptfs incorrectly
validated permissions on the requested mountpoint. A local attacker could
use this flaw to mount to arbitrary locations, leading to privilege
escalation. (CVE-2011-1831)

Vasiliy Kulikov and Dan Rosenberg discovered that eCryptfs incorrectly
validated permissions on the requested mountpoint. A local attacker could
use this flaw to unmount to arbitrary locations, leading to a denial of
service. (CVE-2011-1832)

Vasiliy Kulikov and Dan Rosenberg discovered that eCryptfs incorrectly
validated permissions on the requested source directory. A local attacker
could use this flaw to mount an arbitrary directory, possibly leading to
information disclosure. A pending kernel update will provide the other
half of the fix for this issue. (CVE-2011-1833)

Dan Rosenberg and Marc Deslauriers discovered that eCryptfs incorrectly
handled modifications to the mtab file when an error occurs. A local
attacker could use this flaw to corrupt the mtab file, and possibly unmount
arbitrary locations, leading to a denial of service. (CVE-2011-1834)

Marc Deslauriers discovered that eCryptfs incorrectly handled keys when
setting up an encrypted private directory. A local attacker could use this
flaw to manipulate keys during creation of a new user. (CVE-2011-1835)

Marc Deslauriers discovered that eCryptfs incorrectly handled permissions
during recovery. A local attacker could use this flaw to possibly access
another user's data during the recovery process. This issue only applied to
Ubuntu 11.04. (CVE-2011-1836)

Vasiliy Kulikov discovered that eCryptfs incorrectly handled lock counters.
A local attacker could use this flaw to possibly overwrite arbitrary files.
The default symlink restrictions in Ubuntu 10.10 and 11.04 should protect
against this issue. (CVE-2011-1837)");

  script_tag(name:"affected", value:"'ecryptfs-utils' package(s) on Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ecryptfs-utils", ver:"83-0ubuntu3.2.10.04.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU10.10") {

  if(!isnull(res = isdpkgvuln(pkg:"ecryptfs-utils", ver:"83-0ubuntu3.2.10.10.1", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"ecryptfs-utils", ver:"87-0ubuntu1.1", rls:"UBUNTU11.04"))) {
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
