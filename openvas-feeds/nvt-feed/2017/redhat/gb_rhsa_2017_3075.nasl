# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812056");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2017-10-27 14:30:52 +0200 (Fri, 27 Oct 2017)");
  script_cve_id("CVE-2017-13089", "CVE-2017-13090");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-30 02:29:00 +0000 (Sat, 30 Dec 2017)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for wget RHSA-2017:3075-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'wget'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The wget packages provide the GNU
  Wget file retrieval utility for HTTP, HTTPS, and FTP protocols.

Security Fix(es):

  * A stack-based and a heap-based buffer overflow flaws were found in wget
when processing chunked encoded HTTP responses. By tricking an unsuspecting
user into connecting to a malicious HTTP server, an attacker could exploit
these flaws to potentially execute arbitrary code. (CVE-2017-13089,
CVE-2017-13090)

Red Hat would like to thank the GNU Wget project for reporting these
issues.");
  script_tag(name:"affected", value:"wget on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2017:3075-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-October/msg00038.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"wget", rpm:"wget~1.14~15.el7_4.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wget-debuginfo", rpm:"wget-debuginfo~1.14~15.el7_4.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
