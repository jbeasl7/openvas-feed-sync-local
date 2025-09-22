# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.853765");
  script_version("2025-04-25T15:41:53+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-25 15:41:53 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"creation_date", value:"2021-04-21 03:01:06 +0000 (Wed, 21 Apr 2021)");
  script_name("openSUSE: Security Advisory for irssi (openSUSE-SU-2021:0587-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0587-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/IWZLMEBAAR5OLPQC7PWZHARHSMCZNVIM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'irssi'
  package(s) announced via the openSUSE-SU-2021:0587-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for irssi fixes the following issues:

     irssi was updated to 1.2.3 (boo#1184848)

  - Fix the compilation of utf8proc (#1021)

  - Fix wrong call to free. By Zero King (#1076)

  - Fix a colour reset in true colour themes when encountering mIRC colours
       (#1059)

  - Fix memory leak on malformed CAP requests (#1120)

  - Fix an erroneous free of SASL data. Credit to Oss-Fuzz (#1128, #1130)

  - Re-set the TLS flag when reconnecting (#1027, #1134)

  - Fix the scrollback getting stuck after /clear (#1115, #1136)

  - Fix the input of Ctrl+C as the first character (#1153, #1154)

  - Fix crash on quit during unloading of modules on certain platforms
       (#1167)

  - Fix Irssi freezing input after Ctrl+Space on GLib  2.62 (#1180, #1183)

  - Fix layout of IDCHANs. By Lauri Tirkkonen (#1197)

  - Fix crash when server got reconnected before it was properly connected
       (#1210, #1211)

  - Fix multiple identical active caps (#1249)

  - Minor help corrections (#1156, #1213, #1214, #1255)

  - Remove erroneous colour in the colorless theme. Reported and fixed by
       Nutchanon Wetchasit (#1220, #1221)

  - Fix invalid bounds calculation when editing the text entry. Found and
       fixed by Sergey Valentey (#1269)

  - Fix passing of negative size in buffer writes. Found and fixed by Sergey
       Valentey (#1270)

  - Fix Irssi freezing on slow hardware and fast DCC transfers (#159, #1271)

  - Fix compilation on Solaris (#1291)

  - Fix null pointer dereference when receiving broken JOIN record. Credit
       to Oss-Fuzz (#1292)

  - Fix crash on /connect to some sockets (#1239, #1298)

  - Fix Irssi rendering on Apple ARM. By Misty De Mo (#1267, #1268, #1290)

  - Fix crash on /lastlog with broken lines (#1281, #1299)

  - Fix memory leak when receiving bogus SASL authentication data. Found and
       fixed by Sergey Valentey (#1293)");

  script_tag(name:"affected", value:"'irssi' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"irssi", rpm:"irssi~1.2.3~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"irssi-debuginfo", rpm:"irssi-debuginfo~1.2.3~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"irssi-debugsource", rpm:"irssi-debugsource~1.2.3~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"irssi-devel", rpm:"irssi-devel~1.2.3~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
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
