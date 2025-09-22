# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871540");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2016-01-15 06:14:43 +0100 (Fri, 15 Jan 2016)");
  script_cve_id("CVE-2016-0777", "CVE-2016-0778");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for openssh RHSA-2016:0043-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"OpenSSH is OpenBSD's SSH (Secure Shell)
protocol implementation. These packages include the core files necessary for
both the OpenSSH client and server.

An information leak flaw was found in the way the OpenSSH client roaming
feature was implemented. A malicious server could potentially use this flaw
to leak portions of memory (possibly including private SSH keys) of a
successfully authenticated OpenSSH client. (CVE-2016-0777)

A buffer overflow flaw was found in the way the OpenSSH client roaming
feature was implemented. A malicious server could potentially use this flaw
to execute arbitrary code on a successfully authenticated OpenSSH client if
that client used certain non-default configuration options. (CVE-2016-0778)

Red Hat would like to thank Qualys for reporting these issues.

All openssh users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing this
update, the OpenSSH server daemon (sshd) will be restarted automatically.");
  script_tag(name:"affected", value:"openssh on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2016:0043-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-January/msg00020.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"openssh", rpm:"openssh~6.6.1p1~23.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~6.6.1p1~23.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~6.6.1p1~23.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-debuginfo", rpm:"openssh-debuginfo~6.6.1p1~23.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-keycat", rpm:"openssh-keycat~6.6.1p1~23.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~6.6.1p1~23.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
