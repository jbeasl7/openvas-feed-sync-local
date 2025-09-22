# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.894147");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-01-14 14:29:35 +0100 (Thu, 14 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.147: Sichere Nutzung von EFS unter Windows - Windows");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04147.html");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz-deprecated");

  script_tag(name:"summary", value:"IT-Grundschutz M4.147: Sichere Nutzung von EFS unter Windows (Windows).

  ACHTUNG: Dieser Test wird nicht mehr unterstützt. Er wurde ersetzt durch
  den entsprechenden Test der nun permanent and die aktuelle EL angepasst
  wird: OID 1.3.6.1.4.1.25623.1.0.94217

  Diese Prüfung bezieht sich auf die 11. Ergänzungslieferung (11. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maßnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Ergänzungslieferung bezieht. Titel und Inhalt können sich bei einer
  Aktualisierung ändern, allerdings nicht die Kernthematik.

  *********************************ACHTUNG**************************************

  Diese Prüfung weicht von der offiziellen Ergänzungslieferung 11 ab.

  Grund:
  Folgende Satz in der M4.147 ist nicht korrekt:
  'Aus diesem Grund sollte der Ruhezustand bei Verwendung von EFS unter
  Windows Versionen vor Windows Vista nicht verwendet werden. Dies ist
  besonders bei Laptops wichtig. Unter Windows Vista kann als Abhilfe die
  Auslagerungsdatei verschlüsselt werden: Computerkonfiguration   Windows
  Einstellungen   Sicherheitseinstellungen   Richtlinien für öffentlicher
  Schlüssel   Verschlüsseltes Dateisystem. Klick mit der rechten Maustaste
  und Wahl von Eigenschaften im dann angezeigten Menü aktivieren.'

  Besser müsste er wie folgt formuliert werden.

  'Aus diesem Grund sollte der Ruhezustand bei Verwendung von EFS nicht
  verwendet werden. Dies ist besonders bei Laptops wichtig. Ab der Version
  Windows Vista kann als Abhilfe die Festplattenverschlüsselung BitLocker
  eingesetzt werden, die auch die Ruhezustandsdatei verschlüsselt.'

  Dieser Fehler wurde von der IT-Grundschutz Koordinierungsstelle
  bestätigt und wird mit der nächsten Ergänzungslieferung korrigiert.

  Hinweis:

  Die Maßnahme ist in EL11 technisch fehlerhaft.
  Der Test führt abweichend von der Maßnahme den korrekten Test aus.");
  script_tag(name:"deprecated", value:TRUE);
  exit(0);
}

exit(66);
