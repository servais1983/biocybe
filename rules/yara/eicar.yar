/*
    Règle de détection EICAR — standard industriel de test antivirus.
    https://www.eicar.org/download-anti-malware-testfile/

    NE PAS supprimer : utilisée par la suite d'intégration de BioCybe
    pour valider que la chaîne complète (chargement règles → scan →
    alerte → quarantaine) fonctionne sans nécessiter de vrai malware.
*/

rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test file (standard industriel)"
        author      = "BioCybe Team"
        date        = "2026-05-17"
        reference   = "https://www.eicar.org/"
        severity    = "low"
        family      = "EICAR"
        category    = "test"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}
