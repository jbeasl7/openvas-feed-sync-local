# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0481.1");
  script_cve_id("CVE-2015-8605");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:08 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-01-19 17:07:20 +0000 (Tue, 19 Jan 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0481-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0481-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160481-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/880984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/926159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928390");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936923");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/947780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961305");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-February/001886.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dhcp' package(s) announced via the SUSE-SU-2016:0481-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dhcp fixes the following issues:

- CVE-2015-8605: A remote attacker could have used badly formed packets with an invalid IPv4 UDP length field to cause a DHCP server, client, or relay program to terminate abnormally (bsc#961305)

The following bugs were fixed:

- bsc#936923: Improper lease duration checking
- bsc#880984: Integer overflows in the date and time handling code
- bsc#947780: DHCP server could abort with 'Unable to set up timer: out of range' on very long or infinite timer intervals / lease lifetimes
- bsc#926159: DHCP preferrend and valid lifetime would be logged incorrectly
- bsc#928390: dhclient dit not expose next-server DHCPv4 option to script
- bsc#926159: DHCP preferrend and valid lifetime would be logged incorrectly");

  script_tag(name:"affected", value:"'dhcp' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Desktop 11-SP4, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP3, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"dhcp", rpm:"dhcp~4.2.4.P2~0.24.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-client", rpm:"dhcp-client~4.2.4.P2~0.24.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-relay", rpm:"dhcp-relay~4.2.4.P2~0.24.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-server", rpm:"dhcp-server~4.2.4.P2~0.24.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"dhcp", rpm:"dhcp~4.2.4.P2~0.24.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-client", rpm:"dhcp-client~4.2.4.P2~0.24.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-relay", rpm:"dhcp-relay~4.2.4.P2~0.24.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-server", rpm:"dhcp-server~4.2.4.P2~0.24.1", rls:"SLES11.0SP4"))) {
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
