# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871059");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2013-10-29 13:27:15 +0530 (Tue, 29 Oct 2013)");
  script_cve_id("CVE-2012-6085", "CVE-2013-4242", "CVE-2013-4351", "CVE-2013-4402");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("RedHat Update for gnupg RHSA-2013:1458-01");


  script_tag(name:"affected", value:"gnupg on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"insight", value:"The GNU Privacy Guard (GnuPG or GPG) is a tool for encrypting data and
creating digital signatures, compliant with the proposed OpenPGP Internet
standard and the S/MIME standard.

It was found that GnuPG was vulnerable to the Yarom/Falkner flush+reload
cache side-channel attack on the RSA secret exponent. An attacker able to
execute a process on the logical CPU that shared the L3 cache with the
GnuPG process (such as a different local user or a user of a KVM guest
running on the same host with the kernel same-page merging functionality
enabled) could possibly use this flaw to obtain portions of the RSA secret
key. (CVE-2013-4242)

A denial of service flaw was found in the way GnuPG parsed certain
compressed OpenPGP packets. An attacker could use this flaw to send
specially crafted input data to GnuPG, making GnuPG enter an infinite loop
when parsing data. (CVE-2013-4402)

It was found that importing a corrupted public key into a GnuPG keyring
database corrupted that keyring. An attacker could use this flaw to trick a
local user into importing a specially crafted public key into their keyring
database, causing the keyring to be corrupted and preventing its further
use. (CVE-2012-6085)

It was found that GnuPG did not properly interpret the key flags in a PGP
key packet. GPG could accept a key for uses not indicated by its holder.
(CVE-2013-4351)

Red Hat would like to thank Werner Koch for reporting the CVE-2013-4402
issue. Upstream acknowledges Taylor R Campbell as the original reporter.

All gnupg users are advised to upgrade to this updated package, which
contains backported patches to correct these issues.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"RHSA", value:"2013:1458-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-October/msg00027.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnupg'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"gnupg", rpm:"gnupg~1.4.5~18.el5_10", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnupg-debuginfo", rpm:"gnupg-debuginfo~1.4.5~18.el5_10", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
