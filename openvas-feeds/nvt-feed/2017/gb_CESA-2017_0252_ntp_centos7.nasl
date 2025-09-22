# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882653");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2017-02-07 05:45:01 +0100 (Tue, 07 Feb 2017)");
  script_cve_id("CVE-2016-7426", "CVE-2016-7429", "CVE-2016-7433", "CVE-2016-9310",
                "CVE-2016-9311");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-18 18:14:00 +0000 (Thu, 18 Jun 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for ntp CESA-2017:0252 centos7");
  script_tag(name:"summary", value:"Check the version of ntp");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The Network Time Protocol (NTP) is used
to synchronize a computer's time with another referenced time source.
These packages include the ntpd service which continuously adjusts system time
and utilities used to query and configure the ntpd service.

Security Fix(es):

  * It was found that when ntp is configured with rate limiting for all
associations the limits are also applied to responses received from its
configured sources. A remote attacker who knows the sources can cause a
denial of service by preventing ntpd from accepting valid responses from
its sources. (CVE-2016-7426)

  * A flaw was found in the control mode functionality of ntpd. A remote
attacker could send a crafted control mode packet which could lead to
information disclosure or result in DDoS amplification attacks.
(CVE-2016-9310)

  * A flaw was found in the way ntpd implemented the trap service. A remote
attacker could send a specially crafted packet to cause a null pointer
dereference that will crash ntpd, resulting in a denial of service.
(CVE-2016-9311)

  * A flaw was found in the way ntpd running on a host with multiple network
interfaces handled certain server responses. A remote attacker could use
this flaw which would cause ntpd to not synchronize with the source.
(CVE-2016-7429)

  * A flaw was found in the way ntpd calculated the root delay. A remote
attacker could send a specially-crafted spoofed packet to cause denial of
service or in some special cases even crash. (CVE-2016-7433)");
  script_tag(name:"affected", value:"ntp on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2017:0252");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-February/022267.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~25.el7.centos.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntpdate", rpm:"ntpdate~4.2.6p5~25.el7.centos.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.6p5~25.el7.centos.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntp-perl", rpm:"ntp-perl~4.2.6p5~25.el7.centos.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sntp", rpm:"sntp~4.2.6p5~25.el7.centos.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
