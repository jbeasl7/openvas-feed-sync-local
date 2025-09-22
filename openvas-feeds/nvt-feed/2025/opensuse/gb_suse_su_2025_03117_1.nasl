# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.03117.1");
  script_tag(name:"creation_date", value:"2025-09-11 04:06:43 +0000 (Thu, 11 Sep 2025)");
  script_version("2025-09-11T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:03117-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03117-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503117-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243419");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246995");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041555.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'regionServiceClientConfigAzure' package(s) announced via the SUSE-SU-2025:03117-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for regionServiceClientConfigAzure contains the following fixes:

- Update to version 3.0.0.(bsc#1246995)
 + SLE 16 python-requests requires SSL v3 certificates. Update 2
 region server certs to support SLE 16 when it gets released.

- Update dependency name for metadata package, name change in
 SLE 16. (bsc#1243419)

 + Replacing certificate for rgnsrv-azure-southeastasia to get
 rid of weird chain cert");

  script_tag(name:"affected", value:"'regionServiceClientConfigAzure' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"regionServiceClientConfigAzure", rpm:"regionServiceClientConfigAzure~3.0.0~150000.3.28.1", rls:"openSUSELeap15.6"))) {
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
