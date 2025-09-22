# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-April/015755.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880814");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_xref(name:"CESA", value:"2009:0046");
  script_cve_id("CVE-2009-0021");
  script_name("CentOS Update for ntp CESA-2009:0046 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"ntp on CentOS 5");
  script_tag(name:"insight", value:"The Network Time Protocol (NTP) is used to synchronize a computer's time
  with a referenced time source.

  A flaw was discovered in the way the ntpd daemon checked the return value
  of the OpenSSL EVP_VerifyFinal function. On systems using NTPv4
  authentication, this could lead to an incorrect verification of
  cryptographic signatures, allowing time-spoofing attacks. (CVE-2009-0021)

  Note: This issue only affects systems that have enabled NTP authentication.
  By default, NTP authentication is not enabled.

  All ntp users are advised to upgrade to the updated packages, which contain
  a backported patch to resolve this issue. After installing the update, the
  ntpd daemon will restart automatically.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.2p1~9.el5.centos.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
