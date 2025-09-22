# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871110");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2014-01-21 13:25:49 +0530 (Tue, 21 Jan 2014)");
  script_cve_id("CVE-2013-4576");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_name("RedHat Update for gnupg RHSA-2014:0016-01");


  script_tag(name:"affected", value:"gnupg on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"insight", value:"The GNU Privacy Guard (GnuPG or GPG) is a tool for encrypting data and
creating digital signatures, compliant with the proposed OpenPGP Internet
standard and the S/MIME standard.

It was found that GnuPG was vulnerable to side-channel attacks via acoustic
cryptanalysis. An attacker in close range to a target system that is
decrypting ciphertexts could possibly use this flaw to recover the RSA
secret key from that system. (CVE-2013-4576)

Red Hat would like to thank Werner Koch of GnuPG upstream for reporting
this issue. Upstream acknowledges Genkin, Shamir, and Tromer as the
original reporters.

All gnupg users are advised to upgrade to this updated package, which
contains a backported patch to correct this issue.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"RHSA", value:"2014:0016-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-January/msg00005.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnupg'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"gnupg", rpm:"gnupg~1.4.5~18.el5_10.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnupg-debuginfo", rpm:"gnupg-debuginfo~1.4.5~18.el5_10.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
