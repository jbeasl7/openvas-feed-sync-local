# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871465");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-10-27 07:06:56 +0100 (Tue, 27 Oct 2015)");
  script_cve_id("CVE-2015-5300", "CVE-2015-7704");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-18 17:12:00 +0000 (Thu, 18 Jun 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for ntp RHSA-2015:1930-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The Network Time Protocol (NTP) is used to synchronize a computer's time
with a referenced time source.

It was discovered that ntpd as a client did not correctly check timestamps
in Kiss-of-Death packets. A remote attacker could use this flaw to send a
crafted Kiss-of-Death packet to an ntpd client that would increase the
client's polling interval value, and effectively disable synchronization
with the server. (CVE-2015-7704)

It was found that ntpd did not correctly implement the threshold limitation
for the '-g' option, which is used to set the time without any
restrictions. A man-in-the-middle attacker able to intercept NTP traffic
between a connecting client and an NTP server could use this flaw to force
that client to make multiple steps larger than the panic threshold,
effectively changing the time to an arbitrary value. (CVE-2015-5300)

Red Hat would like to thank Aanchal Malhotra, Isaac E. Cohen, and Sharon
Goldberg of Boston University for reporting these issues.

All ntp users are advised to upgrade to these updated packages, which
contain backported patches to resolve these issues. After installing the
update, the ntpd daemon will restart automatically.");
  script_tag(name:"affected", value:"ntp on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Server (v. 7),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:1930-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-October/msg00037.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(7|6)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~19.el7_1.3", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntp-debuginfo", rpm:"ntp-debuginfo~4.2.6p5~19.el7_1.3", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntpdate", rpm:"ntpdate~4.2.6p5~19.el7_1.3", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~5.el6_7.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntp-debuginfo", rpm:"ntp-debuginfo~4.2.6p5~5.el6_7.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntpdate", rpm:"ntpdate~4.2.6p5~5.el6_7.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}