# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1465.1");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:06 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1465-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1465-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161465-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/663413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/726349");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-June/002088.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'NetworkManager-kde4' package(s) announced via the SUSE-SU-2016:1465-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This NetworkManager-kde4 update fixes the following security and non security issues:

- Fixed a long standing security issue. This makes knetworkmanager probe the RADIUS server for a CA certificate subject and hash if no CA certificate is specified. knetworkmanager then stores this data and send it to NetworkManager for it to do a network validation in the absence of a real certificate (bsc#726349)

- Disabled the loading by default of the NetworkManager plasma applet since it doesn't work.
- Fixed a crash due to the use of an uninitialized variable in the plasma applet in case someone runs it manually (bsc#663413)");

  script_tag(name:"affected", value:"'NetworkManager-kde4' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-kde4", rpm:"NetworkManager-kde4~0.9.svn1043876~1.3.15", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-kde4-lang", rpm:"NetworkManager-kde4-lang~0.9.svn1043876~1.3.15", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-kde4-libs", rpm:"NetworkManager-kde4-libs~0.9.svn1043876~1.3.15", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-openvpn-kde4", rpm:"NetworkManager-openvpn-kde4~0.9.svn1043876~1.3.15", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-pptp-kde4", rpm:"NetworkManager-pptp-kde4~0.9.svn1043876~1.3.15", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasmoid-networkmanagement", rpm:"plasmoid-networkmanagement~0.9.svn1043876~1.3.15", rls:"SLES11.0SP4"))) {
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
