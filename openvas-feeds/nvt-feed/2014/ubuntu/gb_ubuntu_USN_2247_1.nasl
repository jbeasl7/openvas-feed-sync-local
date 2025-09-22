# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841862");
  script_cve_id("CVE-2013-1068", "CVE-2013-4463", "CVE-2013-4469", "CVE-2013-6491", "CVE-2013-7130", "CVE-2014-0134", "CVE-2014-0167");
  script_tag(name:"creation_date", value:"2014-06-23 11:07:31 +0000 (Mon, 23 Jun 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-2247-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|13\.10|14\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-2247-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2247-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nova' package(s) announced via the USN-2247-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Darragh O'Reilly discovered that the Ubuntu packaging for OpenStack Nova
did not properly set up its sudo configuration. If a different flaw was
found in OpenStack Nova, this vulnerability could be used to escalate
privileges. This issue only affected Ubuntu 13.10 and Ubuntu 14.04 LTS.
(CVE-2013-1068)

Bernhard M. Wiedemann and Pedraig Brady discovered that OpenStack Nova did
not properly verify the virtual size of a QCOW2 images. A remote
authenticated attacker could exploit this to create a denial of service via
disk consumption. This issue did not affect Ubuntu 14.04 LTS.
(CVE-2013-4463, CVE-2013-4469)

JuanFra Rodriguez Cardoso discovered that OpenStack Nova did not enforce
SSL connections when Nova was configured to use QPid and qpid_protocol is
set to 'ssl'. If a remote attacker were able to perform a machine-in-the-middle
attack, this flaw could be exploited to view sensitive information. Ubuntu
does not use QPid with Nova by default. This issue did not affect Ubuntu
14.04 LTS. (CVE-2013-6491)

Loganathan Parthipan discovered that OpenStack Nova did not properly create
expected files during KVM live block migration. A remote authenticated
attacker could exploit this to obtain root disk snapshot contents via
ephemeral storage. This issue did not affect Ubuntu 14.04 LTS.
(CVE-2013-7130)

Stanislaw Pitucha discovered that OpenStack Nova did not enforce the image
format when rescuing an instance. A remote authenticated attacker could
exploit this to read host files. In the default installation, attackers
would be isolated by the libvirt guest AppArmor profile. This issue only
affected Ubuntu 13.10. (CVE-2014-0134)

Mark Heckmann discovered that OpenStack Nova did not enforce RBAC policy
when adding security group rules via the EC2 API. A remote authenticated
user could exploit this to gain unintended access to this API. This issue
only affected Ubuntu 13.10. (CVE-2014-0167)");

  script_tag(name:"affected", value:"'nova' package(s) on Ubuntu 12.04, Ubuntu 13.10, Ubuntu 14.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python-nova", ver:"2012.1.3+stable-20130423-e52e6912-0ubuntu1.4", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU13.10") {

  if(!isnull(res = isdpkgvuln(pkg:"python-nova", ver:"1:2013.2.3-0ubuntu1.2", rls:"UBUNTU13.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python-nova", ver:"1:2014.1-0ubuntu1.2", rls:"UBUNTU14.04 LTS"))) {
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
