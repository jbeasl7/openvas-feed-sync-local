# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-February/msg00052.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56843");
  script_oid("1.3.6.1.4.1.25623.1.0.870918");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2013-02-22 10:01:35 +0530 (Fri, 22 Feb 2013)");
  script_cve_id("CVE-2012-4543");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name:"RHSA", value:"2013:0511-02");
  script_name("RedHat Update for pki-core RHSA-2013:0511-02");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pki-core'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"pki-core on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Red Hat Certificate System is an enterprise software system designed to
  manage enterprise public key infrastructure (PKI) deployments. PKI Core
  contains fundamental packages required by Red Hat Certificate System, which
  comprise the Certificate Authority (CA) subsystem.

  Note: The Certificate Authority component provided by this advisory cannot
  be used as a standalone server. It is installed and operates as a part of
  Identity Management (the IPA component) in Red Hat Enterprise Linux.

  Multiple cross-site scripting flaws were discovered in Certificate System.
  An attacker could use these flaws to perform a cross-site scripting (XSS)
  attack against victims using Certificate System's web interface.
  (CVE-2012-4543)

  This update also fixes the following bugs:

  * Previously, due to incorrect conversion of large integers while
  generating a new serial number, some of the most significant bits in the
  serial number were truncated. Consequently, the serial number generated for
  certificates was sometimes smaller than expected and this incorrect
  conversion in turn led to a collision if a certificate with the smaller
  number already existed in the database. This update removes the incorrect
  integer conversion so that no serial numbers are truncated. As a result,
  the installation wizard proceeds as expected. (BZ#841663)

  * The certificate authority used a different profile for issuing the audit
  certificate than it used for renewing it. The issuing profile was for two
  years, and the renewal was for six months. They should both be for two
  years. This update sets the default and constraint parameters in the
  caSignedLogCert.cfg audit certificate renewal profile to two years.
  (BZ#844459)

  This update also adds the following enhancements:

  * IPA (Identity, Policy and Audit) now provides an improved way to
  determine that PKI is up and ready to service requests. Checking the
  service status was not sufficient. This update creates a mechanism for
  clients to determine that the PKI subsystem is up using the getStatus()
  function to query the cs.startup_state in CS.cfg. (BZ#858864)

  * This update increases the default root CA validity period from eight
  years to twenty years. (BZ#891985)

  All users of pki-core are advised to upgrade to these updated packages,
  which fix these issues and add these enhancements.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"pki-core-debuginfo", rpm:"pki-core-debuginfo~9.0.3~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-native-tools", rpm:"pki-native-tools~9.0.3~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-symkey", rpm:"pki-symkey~9.0.3~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-ca", rpm:"pki-ca~9.0.3~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-common", rpm:"pki-common~9.0.3~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-java-tools", rpm:"pki-java-tools~9.0.3~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-selinux", rpm:"pki-selinux~9.0.3~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-setup", rpm:"pki-setup~9.0.3~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-silent", rpm:"pki-silent~9.0.3~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-util", rpm:"pki-util~9.0.3~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
